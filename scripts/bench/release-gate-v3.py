#!/usr/bin/env python3
"""Conservative release gate for paired scan samples and stripped binaries.

The process CSVs are separate from Go benchmark samples because benchmark
iterations cannot establish process-level p95 latency or peak RSS.
"""

import argparse
import csv
import math
import re
import statistics
from pathlib import Path

WORKLOADS = (
    "small_files",
    "mixed_heavy_tail",
    "sensitive_dense",
    "duplicate_logs",
)
TARGETS = (
    "darwin-arm64",
    "darwin-amd64",
    "linux-amd64",
    "linux-arm64",
    "windows-amd64.exe",
)
MIN_GEOMEAN_SPEEDUP = 1.75
BENCH = re.compile(r"BenchmarkScanFilesCorpora/([^/]+)/adaptive-\d+\s+\d+\s+(\d+) ns/op")


def read_bench(path):
    samples = {name: [] for name in WORKLOADS}
    for line in path.read_text().splitlines():
        match = BENCH.search(line)
        if match and match.group(1) in samples:
            samples[match.group(1)].append(int(match.group(2)))
    return samples


def read_process(path):
    samples = {name: [] for name in WORKLOADS}
    if path is None:
        return samples
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            if row["workload"] in samples:
                samples[row["workload"]].append(
                    (float(row["seconds"]), int(row["rss_bytes"]))
                )
    return samples


def p95(values):
    values = sorted(values)
    return values[math.ceil(len(values) * 0.95) - 1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-bench", type=Path, required=True)
    parser.add_argument("--candidate-bench", type=Path, required=True)
    parser.add_argument("--baseline-bin-dir", type=Path, required=True)
    parser.add_argument("--candidate-bin-dir", type=Path, required=True)
    parser.add_argument("--baseline-process", type=Path)
    parser.add_argument("--candidate-process", type=Path)
    args = parser.parse_args()
    baseline = read_bench(args.baseline_bench)
    candidate = read_bench(args.candidate_bench)
    baseline_process = read_process(args.baseline_process)
    candidate_process = read_process(args.candidate_process)
    failures = []
    speedups = []
    for name in WORKLOADS:
        before, after = baseline[name], candidate[name]
        if len(before) != 9 or len(after) != 9:
            failures.append(f"{name}: need exactly 9 paired benchmark samples")
            continue
        ratio = statistics.median(before) / statistics.median(after)
        speedups.append(ratio)
        print(f"{name}: median speedup {ratio:.3f}x")
        if ratio < 1 / 1.05:
            failures.append(f"{name}: median slowdown exceeds 5%")
        pb, pc = baseline_process[name], candidate_process[name]
        if len(pb) < 30 or len(pc) < 30:
            failures.append(f"{name}: need 30 process runs for p95 and RSS")
            continue
        before_p95, after_p95 = p95([v[0] for v in pb]), p95([v[0] for v in pc])
        print(f"{name}: process p95 ratio {after_p95 / before_p95:.3f}x")
        if after_p95 > before_p95 * 1.10:
            failures.append(f"{name}: process p95 slowdown exceeds 10%")
        before_rss, after_rss = max(v[1] for v in pb), max(v[1] for v in pc)
        print(f"{name}: peak RSS ratio {after_rss / before_rss:.3f}x")
        if after_rss > before_rss * 1.10:
            failures.append(f"{name}: peak RSS exceeds 110% of baseline")
    if len(speedups) == len(WORKLOADS):
        geo = math.exp(statistics.mean(math.log(ratio) for ratio in speedups))
        print(f"geometric mean throughput speedup: {geo:.3f}x")
        if geo < MIN_GEOMEAN_SPEEDUP:
            failures.append(f"geometric mean throughput below {MIN_GEOMEAN_SPEEDUP:.2f}x")
    for target in TARGETS:
        filename = f"safnari-{target}"
        before = args.baseline_bin_dir / filename
        after = args.candidate_bin_dir / filename
        if not before.is_file() or not after.is_file():
            failures.append(f"{target}: missing comparable stripped binary")
            continue
        old_size, new_size = before.stat().st_size, after.stat().st_size
        print(f"{target}: {new_size:,} bytes, {(1 - new_size / old_size) * 100:.1f}% smaller")
        if target == "darwin-arm64" and new_size > 16 * 1024 * 1024:
            failures.append(f"{target}: exceeds 16 MiB")
        if target != "darwin-arm64" and new_size > old_size * 0.70:
            failures.append(f"{target}: shrink below 30%")
    for failure in failures:
        print(f"BLOCKER: {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
