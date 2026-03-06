#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/artifacts/bench/gate-$(date -u +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"

# Candidate-local thresholds used when the script is run without BASELINE and
# CANDIDATE artifacts. This keeps the existing CI workflow intact.
THROUGHPUT_SYNTH_MIN="${THROUGHPUT_SYNTH_MIN:-1.05}"
THROUGHPUT_SENSITIVE_MIN="${THROUGHPUT_SENSITIVE_MIN:-1.15}"
THROUGHPUT_SMALL_FILES_MIN="${THROUGHPUT_SMALL_FILES_MIN:-1.15}"
THROUGHPUT_MIXED_HEAVY_TAIL_MIN="${THROUGHPUT_MIXED_HEAVY_TAIL_MIN:-1.10}"
THROUGHPUT_DELTA_SECOND_RUN_MIN="${THROUGHPUT_DELTA_SECOND_RUN_MIN:-1.05}"
ALLOC_REDUCTION_MIN="${ALLOC_REDUCTION_MIN:-0.03}"
P95_REGRESSION_MAX="${P95_REGRESSION_MAX:-1.12}"

# Artifact-compare thresholds used when BASELINE and CANDIDATE are supplied.
BASELINE_SYNTH_SPEEDUP_MIN="${BASELINE_SYNTH_SPEEDUP_MIN:-1.20}"
BASELINE_SENSITIVE_SPEEDUP_MIN="${BASELINE_SENSITIVE_SPEEDUP_MIN:-1.25}"
BASELINE_SMALL_FILES_SPEEDUP_MIN="${BASELINE_SMALL_FILES_SPEEDUP_MIN:-1.30}"
BASELINE_MIXED_HEAVY_TAIL_SPEEDUP_MIN="${BASELINE_MIXED_HEAVY_TAIL_SPEEDUP_MIN:-1.20}"
BASELINE_COLLECT_ALLOC_REDUCTION_MIN="${BASELINE_COLLECT_ALLOC_REDUCTION_MIN:-0.30}"
BASELINE_PEAK_RSS_RATIO_MAX="${BASELINE_PEAK_RSS_RATIO_MAX:-1.10}"
BASELINE_DELTA_CACHE_SPEEDUP_MIN="${BASELINE_DELTA_CACHE_SPEEDUP_MIN:-2.50}"

echo "[bench-gate] output directory: $OUT_DIR"

extract_samples() {
  local file="$1"
  local benchmark="$2"
  local metric="$3"
  awk -v benchmark="$benchmark" -v metric="$metric" '
    index($0, benchmark) {
      for (i = 1; i <= NF; i++) {
        if ($i == metric) {
          print $(i-1)
        }
      }
    }
  ' "$file" | sort -n
}

median_value() {
  local -a samples=("$@")
  local count="${#samples[@]}"
  if (( count == 0 )); then
    echo ""
    return
  fi
  echo "${samples[$(( (count - 1) / 2 ))]}"
}

p95_value() {
  local -a samples=("$@")
  local count="${#samples[@]}"
  if (( count == 0 )); then
    echo ""
    return
  fi
  echo "${samples[$(( (count - 1) * 95 / 100 ))]}"
}

ratio() {
  local numerator="$1"
  local denominator="$2"
  awk -v n="$numerator" -v d="$denominator" \
    'BEGIN { if (d == 0) print 0; else printf "%.6f", n / d }'
}

reduction() {
  local baseline="$1"
  local candidate="$2"
  awk -v b="$baseline" -v c="$candidate" \
    'BEGIN { if (b == 0) print 0; else printf "%.6f", (b - c) / b }'
}

assert_ge() {
  local value="$1"
  local threshold="$2"
  local label="$3"
  awk -v v="$value" -v t="$threshold" -v label="$label" '
    BEGIN {
      if (v + 0 >= t + 0) {
        printf "[bench-gate] PASS %-44s value=%s threshold=%s\n", label, v, t
        exit 0
      }
      printf "[bench-gate] FAIL %-44s value=%s threshold=%s\n", label, v, t
      exit 1
    }'
}

assert_le() {
  local value="$1"
  local threshold="$2"
  local label="$3"
  awk -v v="$value" -v t="$threshold" -v label="$label" '
    BEGIN {
      if (v + 0 <= t + 0) {
        printf "[bench-gate] PASS %-44s value=%s threshold=%s\n", label, v, t
        exit 0
      }
      printf "[bench-gate] FAIL %-44s value=%s threshold=%s\n", label, v, t
      exit 1
    }'
}

artifact_file() {
  local base="$1"
  local name="$2"
  if [[ -f "$base" ]]; then
    echo "$base"
    return 0
  fi
  if [[ -f "$base/$name" ]]; then
    echo "$base/$name"
    return 0
  fi
  echo ""
}

median_metric_from_file() {
  local file="$1"
  local benchmark="$2"
  local metric="$3"
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo ""
    return
  fi
  mapfile -t samples < <(extract_samples "$file" "$benchmark" "$metric")
  median_value "${samples[@]}"
}

p95_metric_from_file() {
  local file="$1"
  local benchmark="$2"
  local metric="$3"
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo ""
    return
  fi
  mapfile -t samples < <(extract_samples "$file" "$benchmark" "$metric")
  p95_value "${samples[@]}"
}

extract_report_value() {
  local file="$1"
  local label="$2"
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo ""
    return
  fi
  python3 - "$file" "$label" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
label = sys.argv[2]
text = path.read_text()
match = re.search(rf'{re.escape(label)}: `([^`]+)`', text)
print(match.group(1) if match else "")
PY
}

if [[ -n "${BASELINE:-}" && -n "${CANDIDATE:-}" ]]; then
  echo "[bench-gate] mode: artifact-compare"
  echo "[bench-gate] baseline: $BASELINE"
  echo "[bench-gate] candidate: $CANDIDATE"
  echo "[bench-gate] thresholds: synth>=$BASELINE_SYNTH_SPEEDUP_MIN sensitive>=$BASELINE_SENSITIVE_SPEEDUP_MIN small_files>=$BASELINE_SMALL_FILES_SPEEDUP_MIN mixed_heavy_tail>=$BASELINE_MIXED_HEAVY_TAIL_SPEEDUP_MIN collect_alloc_reduction>=$BASELINE_COLLECT_ALLOC_REDUCTION_MIN peak_rss<=$BASELINE_PEAK_RSS_RATIO_MAX delta_chunk_vs_mtime>=$BASELINE_DELTA_CACHE_SPEEDUP_MIN"

  baseline_scan="$(artifact_file "$BASELINE" "scan-samples.txt")"
  candidate_scan="$(artifact_file "$CANDIDATE" "scan-samples.txt")"
  baseline_sensitive="$(artifact_file "$BASELINE" "sensitive-samples.txt")"
  candidate_sensitive="$(artifact_file "$CANDIDATE" "sensitive-samples.txt")"
  baseline_small="$(artifact_file "$BASELINE" "small-files-samples.txt")"
  candidate_small="$(artifact_file "$CANDIDATE" "small-files-samples.txt")"
  baseline_mixed_ht="$(artifact_file "$BASELINE" "mixed-heavy-tail-samples.txt")"
  candidate_mixed_ht="$(artifact_file "$CANDIDATE" "mixed-heavy-tail-samples.txt")"
  baseline_collect="$(artifact_file "$BASELINE" "collect-file-data-samples.txt")"
  candidate_collect="$(artifact_file "$CANDIDATE" "collect-file-data-samples.txt")"
  candidate_delta_modes="$(artifact_file "$CANDIDATE" "delta-cache-mode-samples.txt")"
  baseline_report="$(artifact_file "$BASELINE" "report.md")"
  candidate_report="$(artifact_file "$CANDIDATE" "report.md")"

  synth_before="$(median_metric_from_file "$baseline_scan" "BenchmarkScanFilesSyntheticTree/adaptive" "ns/op")"
  synth_after="$(median_metric_from_file "$candidate_scan" "BenchmarkScanFilesSyntheticTree/adaptive" "ns/op")"
  sensitive_before="$(median_metric_from_file "$baseline_sensitive" "BenchmarkScanFilesCorpora/sensitive_dense/adaptive" "ns/op")"
  sensitive_after="$(median_metric_from_file "$candidate_sensitive" "BenchmarkScanFilesCorpora/sensitive_dense/adaptive" "ns/op")"
  small_before="$(median_metric_from_file "$baseline_small" "BenchmarkScanFilesCorpora/small_files/adaptive" "ns/op")"
  small_after="$(median_metric_from_file "$candidate_small" "BenchmarkScanFilesCorpora/small_files/adaptive" "ns/op")"
  mixed_ht_before="$(median_metric_from_file "$baseline_mixed_ht" "BenchmarkScanFilesCorpora/mixed_heavy_tail/adaptive" "ns/op")"
  mixed_ht_after="$(median_metric_from_file "$candidate_mixed_ht" "BenchmarkScanFilesCorpora/mixed_heavy_tail/adaptive" "ns/op")"
  collect_alloc_before="$(median_metric_from_file "$baseline_collect" "BenchmarkCollectFileData/reuse-prebuilt-modules" "allocs/op")"
  collect_alloc_after="$(median_metric_from_file "$candidate_collect" "BenchmarkCollectFileData/reuse-prebuilt-modules" "allocs/op")"
  delta_mtime="$(median_metric_from_file "$candidate_delta_modes" "BenchmarkDeltaSecondRunCorpora/duplicate_logs/mtime" "ns/op")"
  delta_chunk="$(median_metric_from_file "$candidate_delta_modes" "BenchmarkDeltaSecondRunCorpora/duplicate_logs/chunk" "ns/op")"
  rss_before="$(extract_report_value "$baseline_report" "peak RSS (KB)")"
  rss_after="$(extract_report_value "$candidate_report" "peak RSS (KB)")"

  if [[ -z "$synth_before" || -z "$synth_after" || -z "$sensitive_before" || -z "$sensitive_after" || -z "$small_before" || -z "$small_after" || -z "$mixed_ht_before" || -z "$mixed_ht_after" || -z "$collect_alloc_before" || -z "$collect_alloc_after" || -z "$delta_mtime" || -z "$delta_chunk" || -z "$rss_before" || -z "$rss_after" ]]; then
    echo "[bench-gate] missing artifact inputs for compare mode" >&2
    exit 1
  fi

  synth_speedup="$(ratio "$synth_before" "$synth_after")"
  sensitive_speedup="$(ratio "$sensitive_before" "$sensitive_after")"
  small_speedup="$(ratio "$small_before" "$small_after")"
  mixed_ht_speedup="$(ratio "$mixed_ht_before" "$mixed_ht_after")"
  collect_alloc_reduction="$(reduction "$collect_alloc_before" "$collect_alloc_after")"
  peak_rss_ratio="$(ratio "$rss_after" "$rss_before")"
  delta_cache_speedup="$(ratio "$delta_mtime" "$delta_chunk")"

  echo "[bench-gate] synthetic adaptive baseline/candidate speedup: $synth_speedup"
  echo "[bench-gate] sensitive adaptive baseline/candidate speedup: $sensitive_speedup"
  echo "[bench-gate] small-files adaptive baseline/candidate speedup: $small_speedup"
  echo "[bench-gate] mixed-heavy-tail adaptive baseline/candidate speedup: $mixed_ht_speedup"
  echo "[bench-gate] collect-file-data alloc reduction: $collect_alloc_reduction"
  echo "[bench-gate] peak RSS ratio candidate/baseline: $peak_rss_ratio"
  echo "[bench-gate] delta cache chunk/mtime speedup: $delta_cache_speedup"

  status=0
  assert_ge "$synth_speedup" "$BASELINE_SYNTH_SPEEDUP_MIN" "synthetic adaptive speedup" || status=1
  assert_ge "$sensitive_speedup" "$BASELINE_SENSITIVE_SPEEDUP_MIN" "sensitive adaptive speedup" || status=1
  assert_ge "$small_speedup" "$BASELINE_SMALL_FILES_SPEEDUP_MIN" "small-files adaptive speedup" || status=1
  assert_ge "$mixed_ht_speedup" "$BASELINE_MIXED_HEAVY_TAIL_SPEEDUP_MIN" "mixed-heavy-tail adaptive speedup" || status=1
  assert_ge "$collect_alloc_reduction" "$BASELINE_COLLECT_ALLOC_REDUCTION_MIN" "collect-file-data alloc reduction" || status=1
  assert_le "$peak_rss_ratio" "$BASELINE_PEAK_RSS_RATIO_MAX" "peak RSS ratio" || status=1
  assert_ge "$delta_cache_speedup" "$BASELINE_DELTA_CACHE_SPEEDUP_MIN" "delta chunk/mtime speedup" || status=1

  if (( status != 0 )); then
    echo "[bench-gate] artifact-compare gate failed"
    exit 1
  fi

  echo "[bench-gate] artifact-compare gate passed"
  exit 0
fi

echo "[bench-gate] mode: candidate-local"
echo "[bench-gate] thresholds: synth>=$THROUGHPUT_SYNTH_MIN sensitive>=$THROUGHPUT_SENSITIVE_MIN small_files>=$THROUGHPUT_SMALL_FILES_MIN mixed_heavy_tail>=$THROUGHPUT_MIXED_HEAVY_TAIL_MIN delta_second_run>=$THROUGHPUT_DELTA_SECOND_RUN_MIN alloc_reduction>=$ALLOC_REDUCTION_MIN p95_regression<=$P95_REGRESSION_MAX"

pushd "$ROOT/src" >/dev/null
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench '^BenchmarkScanFilesSyntheticTree/(adaptive|ultra)$' \
  -benchmem -count=9 ./scanner | tee "$OUT_DIR/synthetic.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench '^BenchmarkScanFilesCorpora/sensitive_dense/(adaptive|ultra)$' \
  -benchmem -count=9 ./scanner | tee "$OUT_DIR/sensitive.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench '^BenchmarkScanFilesCorpora/small_files/(adaptive|ultra)$' \
  -benchmem -count=9 ./scanner | tee "$OUT_DIR/small-files.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench '^BenchmarkScanFilesCorpora/mixed_heavy_tail/(adaptive|ultra)$' \
  -benchmem -count=9 ./scanner | tee "$OUT_DIR/mixed-heavy-tail.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench '^BenchmarkDeltaSecondRunCorpora/duplicate_logs/(adaptive|ultra)$' \
  -benchmem -count=9 ./scanner | tee "$OUT_DIR/delta-second-run.txt"
popd >/dev/null

mapfile -t synth_adaptive_ns < <(extract_samples "$OUT_DIR/synthetic.txt" \
  "BenchmarkScanFilesSyntheticTree/adaptive" "ns/op")
mapfile -t synth_ultra_ns < <(extract_samples "$OUT_DIR/synthetic.txt" \
  "BenchmarkScanFilesSyntheticTree/ultra" "ns/op")
mapfile -t synth_adaptive_alloc < <(extract_samples "$OUT_DIR/synthetic.txt" \
  "BenchmarkScanFilesSyntheticTree/adaptive" "allocs/op")
mapfile -t synth_ultra_alloc < <(extract_samples "$OUT_DIR/synthetic.txt" \
  "BenchmarkScanFilesSyntheticTree/ultra" "allocs/op")
mapfile -t sensitive_adaptive_ns < <(extract_samples "$OUT_DIR/sensitive.txt" \
  "BenchmarkScanFilesCorpora/sensitive_dense/adaptive" "ns/op")
mapfile -t sensitive_ultra_ns < <(extract_samples "$OUT_DIR/sensitive.txt" \
  "BenchmarkScanFilesCorpora/sensitive_dense/ultra" "ns/op")
mapfile -t small_files_adaptive_ns < <(extract_samples "$OUT_DIR/small-files.txt" \
  "BenchmarkScanFilesCorpora/small_files/adaptive" "ns/op")
mapfile -t small_files_ultra_ns < <(extract_samples "$OUT_DIR/small-files.txt" \
  "BenchmarkScanFilesCorpora/small_files/ultra" "ns/op")
mapfile -t mixed_heavy_tail_adaptive_ns < <(extract_samples "$OUT_DIR/mixed-heavy-tail.txt" \
  "BenchmarkScanFilesCorpora/mixed_heavy_tail/adaptive" "ns/op")
mapfile -t mixed_heavy_tail_ultra_ns < <(extract_samples "$OUT_DIR/mixed-heavy-tail.txt" \
  "BenchmarkScanFilesCorpora/mixed_heavy_tail/ultra" "ns/op")
mapfile -t delta_second_run_adaptive_ns < <(extract_samples "$OUT_DIR/delta-second-run.txt" \
  "BenchmarkDeltaSecondRunCorpora/duplicate_logs/adaptive" "ns/op")
mapfile -t delta_second_run_ultra_ns < <(extract_samples "$OUT_DIR/delta-second-run.txt" \
  "BenchmarkDeltaSecondRunCorpora/duplicate_logs/ultra" "ns/op")

synth_adaptive_median="$(median_value "${synth_adaptive_ns[@]}")"
synth_ultra_median="$(median_value "${synth_ultra_ns[@]}")"
synth_adaptive_p95="$(p95_value "${synth_adaptive_ns[@]}")"
synth_ultra_p95="$(p95_value "${synth_ultra_ns[@]}")"
synth_adaptive_alloc_median="$(median_value "${synth_adaptive_alloc[@]}")"
synth_ultra_alloc_median="$(median_value "${synth_ultra_alloc[@]}")"
sensitive_adaptive_median="$(median_value "${sensitive_adaptive_ns[@]}")"
sensitive_ultra_median="$(median_value "${sensitive_ultra_ns[@]}")"
small_files_adaptive_median="$(median_value "${small_files_adaptive_ns[@]}")"
small_files_ultra_median="$(median_value "${small_files_ultra_ns[@]}")"
mixed_heavy_tail_adaptive_median="$(median_value "${mixed_heavy_tail_adaptive_ns[@]}")"
mixed_heavy_tail_ultra_median="$(median_value "${mixed_heavy_tail_ultra_ns[@]}")"
delta_second_run_adaptive_median="$(median_value "${delta_second_run_adaptive_ns[@]}")"
delta_second_run_ultra_median="$(median_value "${delta_second_run_ultra_ns[@]}")"

if [[ -z "$synth_adaptive_median" || -z "$synth_ultra_median" || -z "$sensitive_adaptive_median" || -z "$sensitive_ultra_median" || -z "$small_files_adaptive_median" || -z "$small_files_ultra_median" || -z "$mixed_heavy_tail_adaptive_median" || -z "$mixed_heavy_tail_ultra_median" || -z "$delta_second_run_adaptive_median" || -z "$delta_second_run_ultra_median" ]]; then
  echo "[bench-gate] missing benchmark samples, cannot evaluate gate" >&2
  exit 1
fi

synth_speedup="$(ratio "$synth_adaptive_median" "$synth_ultra_median")"
sensitive_speedup="$(ratio "$sensitive_adaptive_median" "$sensitive_ultra_median")"
small_files_speedup="$(ratio "$small_files_adaptive_median" "$small_files_ultra_median")"
mixed_heavy_tail_speedup="$(ratio "$mixed_heavy_tail_adaptive_median" "$mixed_heavy_tail_ultra_median")"
delta_second_run_speedup="$(ratio "$delta_second_run_adaptive_median" "$delta_second_run_ultra_median")"
alloc_reduction="$(reduction "$synth_adaptive_alloc_median" "$synth_ultra_alloc_median")"
synth_p95_regression="$(ratio "$synth_ultra_p95" "$synth_adaptive_p95")"

echo "[bench-gate] synthetic adaptive median ns/op: $synth_adaptive_median"
echo "[bench-gate] synthetic ultra median ns/op:    $synth_ultra_median"
echo "[bench-gate] sensitive adaptive median ns/op: $sensitive_adaptive_median"
echo "[bench-gate] sensitive ultra median ns/op:    $sensitive_ultra_median"
echo "[bench-gate] small-files adaptive median ns/op: $small_files_adaptive_median"
echo "[bench-gate] small-files ultra median ns/op:    $small_files_ultra_median"
echo "[bench-gate] mixed-heavy-tail adaptive median ns/op: $mixed_heavy_tail_adaptive_median"
echo "[bench-gate] mixed-heavy-tail ultra median ns/op:    $mixed_heavy_tail_ultra_median"
echo "[bench-gate] delta-second-run adaptive median ns/op: $delta_second_run_adaptive_median"
echo "[bench-gate] delta-second-run ultra median ns/op:    $delta_second_run_ultra_median"
echo "[bench-gate] synthetic alloc reduction:       $alloc_reduction"
echo "[bench-gate] synthetic p95 regression ratio:  $synth_p95_regression"

status=0
assert_ge "$synth_speedup" "$THROUGHPUT_SYNTH_MIN" "synthetic throughput speedup" || status=1
assert_ge "$sensitive_speedup" "$THROUGHPUT_SENSITIVE_MIN" "sensitive throughput speedup" || status=1
assert_ge "$small_files_speedup" "$THROUGHPUT_SMALL_FILES_MIN" "small-files throughput speedup" || status=1
assert_ge "$mixed_heavy_tail_speedup" "$THROUGHPUT_MIXED_HEAVY_TAIL_MIN" "mixed-heavy-tail throughput speedup" || status=1
assert_ge "$delta_second_run_speedup" "$THROUGHPUT_DELTA_SECOND_RUN_MIN" "delta second-run throughput speedup" || status=1
assert_ge "$alloc_reduction" "$ALLOC_REDUCTION_MIN" "allocation reduction" || status=1
assert_le "$synth_p95_regression" "$P95_REGRESSION_MAX" "synthetic p95 regression ratio" || status=1

if (( status != 0 )); then
  echo "[bench-gate] performance gate failed"
  exit 1
fi

echo "[bench-gate] performance gate passed"
