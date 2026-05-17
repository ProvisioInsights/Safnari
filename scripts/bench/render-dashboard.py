#!/usr/bin/env python3
"""Render machine-readable and browsable benchmark outputs."""

from __future__ import annotations

import html
import json
import platform
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


BENCH_RE = re.compile(r"^(Benchmark\S+)-\d+\s+(\d+)\s+(.+)$")
METRICS = ("ns/op", "B/op", "allocs/op", "MB/s")


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    index = int((len(values) - 1) * pct)
    return values[index]


def shell_value(args: list[str], cwd: Path) -> str:
    try:
        return subprocess.check_output(
            args, cwd=cwd, stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        return "unknown"


def parse_bench_line(line: str) -> tuple[str, dict[str, float]] | None:
    match = BENCH_RE.match(line.strip())
    if not match:
        return None
    name = match.group(1)
    fields = match.group(3).split()
    parsed: dict[str, float] = {"iterations": float(match.group(2))}
    for idx, field in enumerate(fields):
        if field in METRICS and idx > 0:
            try:
                parsed[field] = float(fields[idx - 1])
            except ValueError:
                pass
    return name, parsed


def parse_reports(out_dir: Path) -> tuple[dict, list[dict]]:
    existing_context = load_existing_context(out_dir)
    sample_sets: dict[tuple[str, str], dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    contexts: dict[str, dict[str, str]] = defaultdict(dict)
    parsed_inputs: set[str] = set()

    for path in sorted(out_dir.glob("*.txt")):
        if path.name == "time-rss.txt":
            continue
        current_pkg = ""
        for line in path.read_text(errors="replace").splitlines():
            if line.startswith("pkg: "):
                current_pkg = line.removeprefix("pkg: ").strip()
                contexts[path.name]["pkg"] = current_pkg
            elif line.startswith("goos: "):
                contexts[path.name]["goos"] = line.removeprefix("goos: ").strip()
            elif line.startswith("goarch: "):
                contexts[path.name]["goarch"] = line.removeprefix("goarch: ").strip()
            elif line.startswith("cpu: "):
                contexts[path.name]["cpu"] = line.removeprefix("cpu: ").strip()
            parsed = parse_bench_line(line)
            if not parsed:
                continue
            bench_name, metrics = parsed
            parsed_inputs.add(path.name)
            key = (path.name, f"{current_pkg}:{bench_name}" if current_pkg else bench_name)
            for metric, value in metrics.items():
                sample_sets[key][metric].append(value)

    benchmark_rows: list[dict] = []
    for (source, name), metric_samples in sorted(sample_sets.items()):
        row = {"source": source, "name": name, "samples": {}}
        for metric, values in sorted(metric_samples.items()):
            row["samples"][metric] = {
                "count": len(values),
                "p50": percentile(values, 0.50),
                "p95": percentile(values, 0.95),
                "min": min(values),
                "max": max(values),
            }
        benchmark_rows.append(row)

    context = {
        "generated_at": existing_context.get("generated_at")
        or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "go_version": shell_value(["go", "version"], out_dir),
        "commit": shell_value(["git", "rev-parse", "--short", "HEAD"], out_dir),
        "ref": shell_value(["git", "rev-parse", "--abbrev-ref", "HEAD"], out_dir),
        "host_os": first_context_value(contexts, "goos") or platform.system().lower(),
        "host_arch": first_context_value(contexts, "goarch")
        or normalize_arch(platform.machine()),
        "inputs": sorted(parsed_inputs),
        "contexts": contexts,
    }
    for key in ("commit", "ref", "go_version", "host_os", "host_arch"):
        if existing_context.get(key):
            context[key] = existing_context[key]
    return context, benchmark_rows


def first_context_value(contexts: dict[str, dict[str, str]], key: str) -> str:
    for name in sorted(contexts):
        value = contexts[name].get(key)
        if value:
            return value
    return ""


def normalize_arch(value: str) -> str:
    normalized = value.lower()
    return {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(normalized, normalized)


def load_existing_context(out_dir: Path) -> dict:
    path = out_dir / "metrics.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    context = payload.get("context", {})
    return context if isinstance(context, dict) else {}


def load_history(out_dir: Path) -> list[dict]:
    path = out_dir / "metrics-history.jsonl"
    if not path.exists():
        return []
    history = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            history.append(payload)
    return history


def ns_to_ms(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value / 1_000_000:.2f}"


def number(value: float | None) -> str:
    if value is None:
        return "n/a"
    if value >= 1000:
        return f"{value:,.0f}"
    return f"{value:.2f}".rstrip("0").rstrip(".")


def find_metric(
    rows: list[dict], source: str, name_suffix: str, metric: str, field: str = "p50"
) -> float | None:
    for row in rows:
        if row["source"] != source:
            continue
        if not row["name"].endswith(name_suffix):
            continue
        return row["samples"].get(metric, {}).get(field)
    return None


def summary_rows(rows: list[dict]) -> list[tuple[str, str, str, str]]:
    specs = [
        ("Synthetic tree", "scan-samples.txt", "BenchmarkScanFilesSyntheticTree/ultra"),
        (
            "Sensitive dense",
            "sensitive-samples.txt",
            "BenchmarkScanFilesCorpora/sensitive_dense/ultra",
        ),
        (
            "Small files",
            "small-files-samples.txt",
            "BenchmarkScanFilesCorpora/small_files/ultra",
        ),
        (
            "Mixed heavy tail",
            "mixed-heavy-tail-samples.txt",
            "BenchmarkScanFilesCorpora/mixed_heavy_tail/ultra",
        ),
        (
            "Duplicate logs",
            "duplicate-logs-samples.txt",
            "BenchmarkScanFilesCorpora/duplicate_logs/ultra",
        ),
        (
            "Delta second run",
            "delta-second-run-samples.txt",
            "BenchmarkDeltaSecondRunCorpora/duplicate_logs/ultra",
        ),
    ]
    out = []
    for label, source, suffix in specs:
        p50 = find_metric(rows, source, suffix, "ns/op", "p50")
        p95 = find_metric(rows, source, suffix, "ns/op", "p95")
        allocs = find_metric(rows, source, suffix, "allocs/op", "p50")
        out.append((label, ns_to_ms(p50), ns_to_ms(p95), number(allocs)))
    return out


def history_metric(
    run: dict, source: str, name_suffix: str, metric: str, field: str = "p50"
) -> float | None:
    for row in run.get("benchmarks", []):
        if row.get("source") != source:
            continue
        if not str(row.get("name", "")).endswith(name_suffix):
            continue
        samples = row.get("samples", {})
        if not isinstance(samples, dict):
            return None
        value = samples.get(metric, {}).get(field)
        return value if isinstance(value, (int, float)) else None
    return None


def render_history_rows(history: list[dict]) -> str:
    rows = []
    for run in history[-30:]:
        context = run.get("context", {})
        generated = str(context.get("generated_at", "unknown"))
        commit = str(context.get("commit", "unknown"))
        synthetic = history_metric(
            run,
            "scan-samples.txt",
            "BenchmarkScanFilesSyntheticTree/ultra",
            "ns/op",
        )
        duplicate_logs = history_metric(
            run,
            "duplicate-logs-samples.txt",
            "BenchmarkScanFilesCorpora/duplicate_logs/ultra",
            "ns/op",
        )
        delta = history_metric(
            run,
            "delta-second-run-samples.txt",
            "BenchmarkDeltaSecondRunCorpora/duplicate_logs/ultra",
            "ns/op",
        )
        rows.append(
            "<tr>"
            f"<td>{html.escape(generated)}</td>"
            f"<td>{html.escape(commit)}</td>"
            f"<td>{ns_to_ms(synthetic)}</td>"
            f"<td>{ns_to_ms(duplicate_logs)}</td>"
            f"<td>{ns_to_ms(delta)}</td>"
            "</tr>"
        )
    if not rows:
        return (
            "<tr><td colspan=\"5\">History begins after the first published "
            "GitHub Pages deployment.</td></tr>"
        )
    return "\n".join(rows)


def render_html(context: dict, rows: list[dict], history: list[dict]) -> str:
    summary = summary_rows(rows)
    summary_html = "\n".join(
        "<tr>"
        f"<td>{html.escape(label)}</td>"
        f"<td>{p50}</td>"
        f"<td>{p95}</td>"
        f"<td>{allocs}</td>"
        "</tr>"
        for label, p50, p95, allocs in summary
    )

    detail_rows = []
    for row in rows:
        ns = row["samples"].get("ns/op", {})
        bytes_op = row["samples"].get("B/op", {})
        allocs = row["samples"].get("allocs/op", {})
        detail_rows.append(
            "<tr>"
            f"<td>{html.escape(row['source'])}</td>"
            f"<td>{html.escape(row['name'])}</td>"
            f"<td>{ns_to_ms(ns.get('p50'))}</td>"
            f"<td>{ns_to_ms(ns.get('p95'))}</td>"
            f"<td>{number(bytes_op.get('p50'))}</td>"
            f"<td>{number(allocs.get('p50'))}</td>"
            f"<td>{number(ns.get('count'))}</td>"
            "</tr>"
        )
    details_html = "\n".join(detail_rows)
    history_html = render_history_rows(history)

    generated = html.escape(context["generated_at"])
    commit = html.escape(context["commit"])
    go_version = html.escape(context["go_version"])
    host = html.escape(f"{context['host_os']} / {context['host_arch']}")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Safnari Performance Dashboard</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #f7f8fb;
      --fg: #111827;
      --muted: #5b6472;
      --panel: #ffffff;
      --line: #d8dee9;
      --accent: #0f766e;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #0b1020;
        --fg: #eef2ff;
        --muted: #a6adbb;
        --panel: #131a2c;
        --line: #273246;
        --accent: #2dd4bf;
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--fg);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    header, main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px;
    }}
    header {{
      padding-top: 40px;
      padding-bottom: 16px;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: clamp(2rem, 5vw, 3.4rem);
      letter-spacing: 0;
      line-height: 1.05;
    }}
    h2 {{
      margin: 34px 0 14px;
      font-size: 1.15rem;
      letter-spacing: 0;
    }}
    p {{ margin: 0; color: var(--muted); }}
    .meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 10px;
      margin-top: 22px;
    }}
    .stat {{
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 8px;
      padding: 14px 16px;
    }}
    .stat span {{
      display: block;
      color: var(--muted);
      font-size: 0.82rem;
    }}
    .stat strong {{
      display: block;
      margin-top: 4px;
      font-size: 0.98rem;
      overflow-wrap: anywhere;
    }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
    }}
    table {{
      border-collapse: collapse;
      min-width: 760px;
      width: 100%;
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      text-align: right;
      vertical-align: top;
      font-size: 0.92rem;
    }}
    th {{
      color: var(--muted);
      font-weight: 650;
      background: color-mix(in srgb, var(--panel), var(--bg) 40%);
    }}
    td:first-child, th:first-child,
    td:nth-child(2), th:nth-child(2) {{
      text-align: left;
    }}
    tr:last-child td {{ border-bottom: 0; }}
    a {{ color: var(--accent); }}
    footer {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 6px 28px 40px;
      color: var(--muted);
      font-size: 0.9rem;
    }}
  </style>
</head>
<body>
  <header>
    <h1>Safnari Performance Dashboard</h1>
    <p>Latest benchmark artifact rendered by the GitHub Performance workflow.</p>
    <section class="meta" aria-label="Run metadata">
      <div class="stat"><span>Generated</span><strong>{generated}</strong></div>
      <div class="stat"><span>Commit</span><strong>{commit}</strong></div>
      <div class="stat"><span>Go</span><strong>{go_version}</strong></div>
      <div class="stat"><span>Host</span><strong>{host}</strong></div>
    </section>
  </header>
  <main>
    <h2>Tracked Workloads</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Workload</th><th>p50 ms/op</th><th>p95 ms/op</th><th>allocs/op</th></tr>
        </thead>
        <tbody>
          {summary_html}
        </tbody>
      </table>
    </div>
    <h2>All Benchmark Samples</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Source</th><th>Benchmark</th><th>p50 ms/op</th><th>p95 ms/op</th>
            <th>B/op</th><th>allocs/op</th><th>samples</th>
          </tr>
        </thead>
        <tbody>
          {details_html}
        </tbody>
      </table>
    </div>
    <h2>Run History</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Generated</th><th>Commit</th><th>Synthetic p50 ms/op</th>
            <th>Duplicate logs p50 ms/op</th><th>Delta second-run p50 ms/op</th>
          </tr>
        </thead>
        <tbody>
          {history_html}
        </tbody>
      </table>
    </div>
  </main>
  <footer>
    Machine-readable data is published beside this page as
    <a href="metrics.json">metrics.json</a>; the markdown run report is
    available as <a href="report.md">report.md</a>; historical runs are kept in
    <a href="metrics-history.jsonl">metrics-history.jsonl</a>.
  </footer>
</body>
</html>
"""


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: render-dashboard.py <benchmark-artifact-dir>", file=sys.stderr)
        return 2
    out_dir = Path(sys.argv[1]).resolve()
    if not out_dir.is_dir():
        print(f"benchmark artifact directory not found: {out_dir}", file=sys.stderr)
        return 1

    context, benchmarks = parse_reports(out_dir)
    payload = {"context": context, "benchmarks": benchmarks}
    metrics_json = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    (out_dir / "metrics.json").write_text(metrics_json)

    site_dir = out_dir / "site"
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / "metrics.json").write_text(metrics_json)
    history = load_history(out_dir)
    history_path = out_dir / "metrics-history.jsonl"
    history_text = history_path.read_text(errors="replace") if history_path.exists() else ""
    (site_dir / "metrics-history.jsonl").write_text(history_text)
    report_path = out_dir / "report.md"
    if report_path.exists():
        (site_dir / "report.md").write_text(report_path.read_text(errors="replace"))
    (site_dir / "index.html").write_text(render_html(context, benchmarks, history))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
