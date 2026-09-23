#!/usr/bin/env python3
"""Run paired warm-cache collector processes and verify retained scan evidence.

Runs on Unix hosts with wait4. It does not claim cold-cache performance.
"""

import argparse
import csv
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time
from pathlib import Path

WORKLOADS = (
    "small_files", "mixed_heavy_tail", "sensitive_dense", "duplicate_logs",
    "wide_deep", "bounded_content",
)
EVIDENCE_FIELDS = (
    "hashes", "search_hits", "sensitive_data_match_counts", "sensitive_data_truncated",
    "content_scan_bytes", "content_scan_truncated", "collection_warnings",
)


def write_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def build_corpora(root):
    for i in range(128):
        write_file(root / "small_files" / f"dir-{i // 16:02d}" / f"file-{i:03d}.txt",
                   b"ALPHA test@example.com api_key=abcd1234\n")
    for i in range(80):
        write_file(root / "mixed_heavy_tail" / f"small-{i:03d}.txt",
                   b"ALPHA ordinary text\n")
    for i in range(4):
        write_file(root / "mixed_heavy_tail" / f"large-{i:02d}.txt",
                   b"ALPHA test@example.com\n" * 100000)
    for i in range(32):
        write_file(root / "sensitive_dense" / f"dense-{i:03d}.txt",
                   b"ALPHA test@example.com api_key=abcd1234\n" * 1000)
    for i in range(64):
        write_file(root / "duplicate_logs" / f"log-{i:03d}.txt",
                   b"ALPHA test@example.com\n" * 500)
    for i in range(256):
        write_file(root / "wide_deep" / f"branch-{i:03d}" / "file.txt",
                   b"ALPHA test@example.com\n")
    deep = root / "wide_deep" / "deep"
    for i in range(12):
        deep = deep / f"level-{i:02d}"
        write_file(deep / "file.txt", b"ALPHA api_key=abcd1234\n")
    for i in range(8):
        write_file(root / "bounded_content" / f"large-{i:02d}.txt",
                   b"ALPHA test@example.com\n" * 130000)


def corpus_digest(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(root)).encode())
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def evidence_digest(output_path, root):
    records = []
    for line in output_path.read_text().splitlines():
        record = json.loads(line)
        if record.get("record_type") != "file":
            continue
        payload = record["payload"]
        selected = {key: payload.get(key) for key in EVIDENCE_FIELDS}
        selected["path"] = str(Path(payload["path"]).relative_to(root))
        records.append(selected)
    records.sort(key=lambda value: value["path"])
    data = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest(), len(records)


def run(binary, corpus, output_path):
    args = [
        str(binary), "--path", str(corpus), "--output", str(output_path),
        "--hashes", "md5", "--search", "ALPHA,email", "--scan-sensitive",
        "--include-sensitive-data-types", "email,api_key,aws_access_key,jwt_token,ssn",
        "--sensitive-engine", "hybrid", "--sensitive-longtail", "sampled",
        "--max-file-size", str(4 << 20), "--content-scan-max-bytes", str(1 << 20),
        "--concurrency", "2", "--max-io-per-second", "0", "--auto-tune=false",
        "--collect-xattrs=false", "--collect-acl=false", "--redact-sensitive", "mask",
    ]
    started = time.perf_counter()
    with open(os.devnull, "wb") as sink:
        child = subprocess.Popen(args, stdout=sink, stderr=sink)
        _, status, usage = os.wait4(child.pid, 0)
        child.returncode = os.waitstatus_to_exitcode(status)
    duration = time.perf_counter() - started
    if child.returncode != 0:
        raise RuntimeError(f"{binary.name} exited {child.returncode} on {corpus.name}")
    rss = usage.ru_maxrss if platform.system() == "Darwin" else usage.ru_maxrss * 1024
    digest, count = evidence_digest(output_path, corpus)
    output_path.unlink()
    return duration, rss, digest, count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=30)
    args = parser.parse_args()
    if not hasattr(os, "wait4"):
        parser.error("this harness requires Unix wait4; use a native Windows harness there")
    if args.runs < 1:
        parser.error("--runs must be positive")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="safnari-release-corpus-") as temp:
        root = Path(temp)
        build_corpora(root)
        manifest = {
            "platform": platform.platform(), "corpus_sha256": corpus_digest(root),
            "baseline_binary_sha256": hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
            "candidate_binary_sha256": hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
            "runs_per_workload": args.runs,
            "cache_state": "timed runs after one priming invocation per binary; cold cache not controlled",
        }
        (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        rows = {"baseline": [], "candidate": []}
        first_pass = []
        for workload in WORKLOADS:
            expected = None
            corpus = root / workload
            for label, binary in (("baseline", args.baseline), ("candidate", args.candidate)):
                output = root / f"first-{label}-{workload}.ndjson"
                seconds, rss, evidence, count = run(binary, corpus, output)
                if expected is None:
                    expected = (evidence, count)
                if (evidence, count) != expected:
                    raise RuntimeError(f"first-pass retained evidence mismatch: {label} {workload}")
                first_pass.append((label, workload, seconds, rss))
            for index in range(args.runs):
                # Alternate order to reduce drift from cache and host load.
                order = ("baseline", "candidate") if index % 2 == 0 else (
                    "candidate", "baseline")
                for label in order:
                    binary = args.baseline if label == "baseline" else args.candidate
                    output = root / f"out-{label}-{workload}-{index}.ndjson"
                    seconds, rss, evidence, count = run(binary, corpus, output)
                    if expected is None:
                        expected = (evidence, count)
                    if (evidence, count) != expected:
                        raise RuntimeError(f"retained evidence mismatch: {label} {workload} run {index}")
                    rows[label].append((workload, seconds, rss))
            print(f"{workload}: {args.runs} paired runs, {expected[1]} matching file records")
        for label in rows:
            with (args.output_dir / f"{label}.csv").open("w", newline="") as handle:
                writer = csv.writer(handle, lineterminator="\n")
                writer.writerow(("workload", "seconds", "rss_bytes"))
                writer.writerows(rows[label])
        with (args.output_dir / "first-pass.csv").open("w", newline="") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(("binary", "workload", "seconds", "rss_bytes"))
            writer.writerows(first_pass)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
