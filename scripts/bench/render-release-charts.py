#!/usr/bin/env python3
"""Render GitHub-readable release charts from the controlled gate artifact."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from xml.sax.saxutils import escape


WORKLOADS = (
    ("small_files", "Small files"),
    ("mixed_heavy_tail", "Mixed heavy tail"),
    ("sensitive_dense", "Sensitive dense"),
    ("duplicate_logs", "Duplicate logs"),
)
TARGETS = (
    ("darwin-arm64", "macOS ARM64"),
    ("darwin-amd64", "macOS Intel"),
    ("linux-amd64", "Linux AMD64"),
    ("linux-arm64", "Linux ARM64"),
    ("windows-amd64.exe", "Windows AMD64"),
)
INK = "#14263d"
MUTED = "#526579"
BLUE = "#2866a3"
TEAL = "#087f77"
GRID = "#dbe3e9"
PAPER = "#ffffff"
BASELINE = "#657587"


def svg_text(x: float, y: float, value: str, size: int = 18, fill: str = INK,
             weight: int = 400, anchor: str = "start") -> str:
    return (f'<text x="{x}" y="{y}" fill="{fill}" font-size="{size}" '
            f'font-weight="{weight}" text-anchor="{anchor}" '
            f'font-family="Arial, Helvetica, sans-serif">{escape(value)}</text>')


def svg_doc(title: str, description: str, content: list[str], height: int) -> str:
    return "\n".join([
        '<svg xmlns="http://www.w3.org/2000/svg" width="960" '
        f'height="{height}" viewBox="0 0 960 {height}" role="img" '
        'aria-labelledby="title description">',
        f'<title id="title">{escape(title)}</title>',
        f'<desc id="description">{escape(description)}</desc>',
        f'<rect width="960" height="{height}" fill="{PAPER}"/>',
        *content,
        '</svg>',
        '',
    ])


def read_gate(path: Path) -> tuple[dict[str, float], float, dict[str, tuple[int, float]]]:
    text = path.read_text()
    speedups = {
        name: float(value)
        for name, value in re.findall(r"(?m)^([a-z_]+): median speedup ([0-9.]+)x$", text)
    }
    mean_match = re.search(r"geometric mean throughput speedup: ([0-9.]+)x", text)
    sizes = {
        name: (int(size.replace(",", "")), float(shrink))
        for name, size, shrink in re.findall(
            r"(?m)^([a-z0-9.-]+): ([0-9,]+) bytes, ([0-9.]+)% smaller$", text
        )
    }
    if not mean_match or set(speedups) != {name for name, _ in WORKLOADS}:
        raise ValueError("gate output does not contain the four expected workloads")
    if set(sizes) != {name for name, _ in TARGETS}:
        raise ValueError("gate output does not contain the five expected binaries")
    if "BLOCKER:" in text:
        raise ValueError("refusing to chart a failed release gate as a pass")
    return speedups, float(mean_match.group(1)), sizes


def throughput_chart(speedups: dict[str, float], mean: float, source: dict) -> str:
    content = [
        svg_text(48, 52, "Scan throughput by workload", 28, weight=700),
        svg_text(48, 82, "Warm-cache scan-only comparison at equivalent coverage", 16,
                 MUTED),
        svg_text(912, 51, f"{mean:.2f}×", 30, TEAL, 700, "end"),
        svg_text(912, 76, "geometric mean", 14, MUTED, anchor="end"),
    ]
    left, span, top, step = 245, 575, 145, 55
    for tick in range(0, 6):
        x = left + span * tick / 5
        content.append(f'<line x1="{x:.1f}" y1="121" x2="{x:.1f}" y2="363" '
                       f'stroke="{BASELINE if tick == 0 else GRID}" stroke-width="1"/>')
        content.append(svg_text(x, 388, f"{tick}×", 13, MUTED, anchor="middle"))
    goal_x = left + span * 2 / 5
    content.append(f'<line x1="{goal_x:.1f}" y1="118" x2="{goal_x:.1f}" y2="363" '
                   f'stroke="{TEAL}" stroke-width="2" stroke-dasharray="6 5"/>')
    content.append(svg_text(goal_x + 7, 113, "2× release target", 13, TEAL, 700))
    for index, (name, label) in enumerate(WORKLOADS):
        y = top + index * step
        value = speedups[name]
        width = span * value / 5
        content.append(svg_text(215, y + 22, label, 17, INK, 600, "end"))
        content.append(f'<rect x="{left}" y="{y}" width="{width:.1f}" height="31" '
                       f'fill="{BLUE}"/>')
        content.append(svg_text(left + width + 12, y + 22, f"{value:.2f}×", 17, INK, 700))
    content.extend([
        svg_text(48, 429, "9 benchmark samples per workload · macOS ARM64 · Go 1.27.1", 14,
                 MUTED),
        svg_text(48, 451, "Frozen source " + source["baseline_source_sha"][:7] +
                 "  →  candidate " + source["candidate_source_sha"][:7] +
                 " · cold cache and delivery excluded", 13, MUTED),
    ])
    return svg_doc("Safnari controlled scan throughput",
                   "Four workload speedups against the frozen source are " +
                   ", ".join(f"{speedups[name]:.3f} times for {label}" for name, label in WORKLOADS) +
                   f". Geometric mean {mean:.3f} times. Two times is the release target.",
                   content, 480)


def size_chart(sizes: dict[str, tuple[int, float]], source: dict) -> str:
    content = [
        svg_text(48, 52, "Stripped executable size", 28, weight=700),
        svg_text(48, 82, "Reduction from equally stripped frozen-source builds", 16, MUTED),
    ]
    left, span, top, step = 280, 510, 132, 51
    for tick in range(0, 51, 10):
        x = left + span * tick / 50
        content.append(f'<line x1="{x:.1f}" y1="112" x2="{x:.1f}" y2="390" '
                       f'stroke="{BASELINE if tick == 0 else GRID}" stroke-width="1"/>')
        content.append(svg_text(x, 413, f"{tick}%", 13, MUTED, anchor="middle"))
    goal_x = left + span * 30 / 50
    content.append(f'<line x1="{goal_x:.1f}" y1="109" x2="{goal_x:.1f}" y2="390" '
                   f'stroke="{TEAL}" stroke-width="2" stroke-dasharray="6 5"/>')
    content.append(svg_text(goal_x + 7, 104, "30% release target", 13, TEAL, 700))
    for index, (name, label) in enumerate(TARGETS):
        y = top + index * step
        size, reduction = sizes[name]
        width = span * reduction / 50
        content.append(svg_text(48, y + 17, label, 17, INK, 600))
        content.append(svg_text(48, y + 35, f"{size / (1024 * 1024):.2f} MiB", 13, MUTED))
        content.append(f'<rect x="{left}" y="{y}" width="{width:.1f}" height="30" '
                       f'fill="{BLUE}"/>')
        content.append(svg_text(left + width + 10, y + 22, f"{reduction:.1f}%", 17, INK, 700))
    arm_size = sizes["darwin-arm64"][0]
    if arm_size > 16 * 1024 * 1024:
        raise ValueError("macOS ARM64 executable exceeds the 16 MiB release limit")
    content.extend([
        svg_text(48, 455, f"macOS ARM64: {arm_size:,} bytes, below the 16 MiB limit", 14,
                 MUTED),
        svg_text(48, 477, "Same Go 1.27.1 toolchain and build flags for both source revisions · "
                 "five cross-compiled targets", 13, MUTED),
    ])
    return svg_doc("Safnari stripped executable size reduction",
                   "Five executable size reductions against equally stripped frozen builds: " +
                   ", ".join(f"{sizes[name][1]:.1f} percent for {label}" for name, label in TARGETS) +
                   ". Thirty percent is the release target.", content, 506)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads((args.evidence / "manifest.json").read_text())
    speedups, mean, sizes = read_gate(args.evidence / "gate-output.txt")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "release-v3-throughput.svg").write_text(
        throughput_chart(speedups, mean, source)
    )
    (args.output_dir / "release-v3-size.svg").write_text(size_chart(sizes, source))


if __name__ == "__main__":
    main()
