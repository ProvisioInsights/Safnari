#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/artifacts/bench/gate-$(date -u +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"

THROUGHPUT_SYNTH_MIN="${THROUGHPUT_SYNTH_MIN:-1.05}"
THROUGHPUT_SENSITIVE_MIN="${THROUGHPUT_SENSITIVE_MIN:-1.15}"
ALLOC_REDUCTION_MIN="${ALLOC_REDUCTION_MIN:-0.03}"
P95_REGRESSION_MAX="${P95_REGRESSION_MAX:-1.12}"

echo "[bench-gate] output directory: $OUT_DIR"
echo "[bench-gate] thresholds: synth>=$THROUGHPUT_SYNTH_MIN sensitive>=$THROUGHPUT_SENSITIVE_MIN alloc_reduction>=$ALLOC_REDUCTION_MIN p95_regression<=$P95_REGRESSION_MAX"

pushd "$ROOT/src" >/dev/null
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench '^BenchmarkScanFilesSyntheticTree/(adaptive|ultra)$' \
  -benchmem -count=9 ./scanner | tee "$OUT_DIR/synthetic.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench '^BenchmarkScanFilesCorpora/sensitive_dense/(adaptive|ultra)$' \
  -benchmem -count=9 ./scanner | tee "$OUT_DIR/sensitive.txt"
popd >/dev/null

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
  awk -v n="$numerator" -v d="$denominator" 'BEGIN { if (d == 0) print 0; else printf "%.6f", n / d }'
}

reduction() {
  local baseline="$1"
  local candidate="$2"
  awk -v b="$baseline" -v c="$candidate" 'BEGIN { if (b == 0) print 0; else printf "%.6f", (b - c) / b }'
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

synth_adaptive_median="$(median_value "${synth_adaptive_ns[@]}")"
synth_ultra_median="$(median_value "${synth_ultra_ns[@]}")"
synth_adaptive_p95="$(p95_value "${synth_adaptive_ns[@]}")"
synth_ultra_p95="$(p95_value "${synth_ultra_ns[@]}")"
synth_adaptive_alloc_median="$(median_value "${synth_adaptive_alloc[@]}")"
synth_ultra_alloc_median="$(median_value "${synth_ultra_alloc[@]}")"
sensitive_adaptive_median="$(median_value "${sensitive_adaptive_ns[@]}")"
sensitive_ultra_median="$(median_value "${sensitive_ultra_ns[@]}")"

if [[ -z "$synth_adaptive_median" || -z "$synth_ultra_median" || -z "$sensitive_adaptive_median" || -z "$sensitive_ultra_median" ]]; then
  echo "[bench-gate] missing benchmark samples, cannot evaluate gate" >&2
  exit 1
fi

synth_speedup="$(ratio "$synth_adaptive_median" "$synth_ultra_median")"
sensitive_speedup="$(ratio "$sensitive_adaptive_median" "$sensitive_ultra_median")"
alloc_reduction="$(reduction "$synth_adaptive_alloc_median" "$synth_ultra_alloc_median")"
synth_p95_regression="$(ratio "$synth_ultra_p95" "$synth_adaptive_p95")"

echo "[bench-gate] synthetic adaptive median ns/op: $synth_adaptive_median"
echo "[bench-gate] synthetic ultra median ns/op:    $synth_ultra_median"
echo "[bench-gate] sensitive adaptive median ns/op: $sensitive_adaptive_median"
echo "[bench-gate] sensitive ultra median ns/op:    $sensitive_ultra_median"
echo "[bench-gate] synthetic alloc reduction:       $alloc_reduction"
echo "[bench-gate] synthetic p95 regression ratio:  $synth_p95_regression"

status=0
assert_ge "$synth_speedup" "$THROUGHPUT_SYNTH_MIN" "synthetic throughput speedup" || status=1
assert_ge "$sensitive_speedup" "$THROUGHPUT_SENSITIVE_MIN" "sensitive throughput speedup" || status=1
assert_ge "$alloc_reduction" "$ALLOC_REDUCTION_MIN" "allocation reduction" || status=1
assert_le "$synth_p95_regression" "$P95_REGRESSION_MAX" "synthetic p95 regression ratio" || status=1

if (( status != 0 )); then
  echo "[bench-gate] performance gate failed"
  exit 1
fi

echo "[bench-gate] performance gate passed"
