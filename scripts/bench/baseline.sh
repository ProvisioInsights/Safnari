#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/artifacts/bench/$(date -u +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"

echo "[bench-baseline] output directory: $OUT_DIR"

pushd "$ROOT/src" >/dev/null
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench \
  'BenchmarkScanFilesSyntheticTree|BenchmarkScanFilesCorpora|BenchmarkTraversal(Deep|Wide)Tree|BenchmarkLooksLikeTextFast' \
  -benchmem ./scanner | tee "$OUT_DIR/benchmark.txt"
go test -run '^$' -bench 'BenchmarkTokenContains' -benchmem ./scanner/prefilter \
  | tee "$OUT_DIR/benchmark-prefilter.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench '^BenchmarkScanFilesSyntheticTree/(adaptive|ultra)$' \
  -benchmem -count=9 ./scanner | tee "$OUT_DIR/scan-samples.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench \
  '^BenchmarkScanFilesCorpora/sensitive_dense/(adaptive|ultra)$' -benchmem -count=9 ./scanner \
  | tee "$OUT_DIR/sensitive-samples.txt"
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

percentile_ms() {
  local -a samples=("$@")
  local count="${#samples[@]}"
  local percentile_index
  if (( count == 0 )); then
    echo "n/a"
    return
  fi
  percentile_index=$(( (count - 1) * 95 / 100 ))
  awk -v ns="${samples[$percentile_index]}" 'BEGIN{printf "%.2f", ns/1000000}'
}

median_ms() {
  local -a samples=("$@")
  local count="${#samples[@]}"
  local median_index
  if (( count == 0 )); then
    echo "n/a"
    return
  fi
  median_index=$(( (count - 1) / 2 ))
  awk -v ns="${samples[$median_index]}" 'BEGIN{printf "%.2f", ns/1000000}'
}

ratio() {
  local numerator="$1"
  local denominator="$2"
  if [[ -z "$numerator" || -z "$denominator" || "$denominator" == "0" ]]; then
    echo "n/a"
    return
  fi
  awk -v n="$numerator" -v d="$denominator" 'BEGIN{printf "%.2f", n/d}'
}

mapfile -t ultra_ns_samples < <(extract_samples "$OUT_DIR/scan-samples.txt" "BenchmarkScanFilesSyntheticTree/ultra" "ns/op")
mapfile -t adaptive_ns_samples < <(extract_samples "$OUT_DIR/scan-samples.txt" "BenchmarkScanFilesSyntheticTree/adaptive" "ns/op")
mapfile -t ultra_sensitive_samples < <(extract_samples "$OUT_DIR/sensitive-samples.txt" \
  "BenchmarkScanFilesCorpora/sensitive_dense/ultra" "ns/op")
mapfile -t adaptive_sensitive_samples < <(extract_samples "$OUT_DIR/sensitive-samples.txt" \
  "BenchmarkScanFilesCorpora/sensitive_dense/adaptive" "ns/op")

p50_ms="$(median_ms "${ultra_ns_samples[@]}")"
p95_ms="$(percentile_ms "${ultra_ns_samples[@]}")"

bytes_per_op="$(awk '/BenchmarkScanFilesSyntheticTree\/ultra/ {
  for (i = 1; i <= NF; i++) if ($i == "B/op") value=$(i-1)
} END {
  if (value != "") print value; else print "n/a"
}' "$OUT_DIR/scan-samples.txt")"

allocs_per_op="$(awk '/BenchmarkScanFilesSyntheticTree\/ultra/ {
  for (i = 1; i <= NF; i++) if ($i == "allocs/op") value=$(i-1)
} END {
  if (value != "") print value; else print "n/a"
}' "$OUT_DIR/scan-samples.txt")"

synthetic_speedup="n/a"
sensitive_speedup="n/a"
if (( ${#adaptive_ns_samples[@]} > 0 && ${#ultra_ns_samples[@]} > 0 )); then
  adaptive_median="${adaptive_ns_samples[$(( (${#adaptive_ns_samples[@]} - 1) / 2 ))]}"
  ultra_median="${ultra_ns_samples[$(( (${#ultra_ns_samples[@]} - 1) / 2 ))]}"
  synthetic_speedup="$(ratio "$adaptive_median" "$ultra_median")"
fi
if (( ${#adaptive_sensitive_samples[@]} > 0 && ${#ultra_sensitive_samples[@]} > 0 )); then
  adaptive_sensitive_median="${adaptive_sensitive_samples[$(( (${#adaptive_sensitive_samples[@]} - 1) / 2 ))]}"
  ultra_sensitive_median="${ultra_sensitive_samples[$(( (${#ultra_sensitive_samples[@]} - 1) / 2 ))]}"
  sensitive_speedup="$(ratio "$adaptive_sensitive_median" "$ultra_sensitive_median")"
fi

peak_rss_kb="n/a"
if command -v /usr/bin/time >/dev/null 2>&1; then
  pushd "$ROOT/src" >/dev/null
  if [[ "$(uname -s)" == "Darwin" ]]; then
    SAFNARI_DISABLE_PROGRESS=1 /usr/bin/time -l go test -run '^$' \
      -bench '^BenchmarkScanFilesSyntheticTree/ultra$' -benchtime=1x ./scanner >/dev/null \
      2>"$OUT_DIR/time-rss.txt" || true
    peak_rss_kb="$(awk '/maximum resident set size/ {print $1}' "$OUT_DIR/time-rss.txt" | tail -n1)"
  else
    SAFNARI_DISABLE_PROGRESS=1 /usr/bin/time -v go test -run '^$' \
      -bench '^BenchmarkScanFilesSyntheticTree/ultra$' -benchtime=1x ./scanner >/dev/null \
      2>"$OUT_DIR/time-rss.txt" || true
    peak_rss_kb="$(awk -F: '/Maximum resident set size/ {gsub(/ /,"",$2); print $2}' \
      "$OUT_DIR/time-rss.txt" | tail -n1)"
  fi
  popd >/dev/null
fi

if [[ -z "$peak_rss_kb" ]]; then
  peak_rss_kb="n/a"
fi

timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
commit="$(git -C "$ROOT" rev-parse --short HEAD)"

sed \
  -e "s/<timestamp>/$timestamp/g" \
  -e "s/<commit>/$commit/g" \
  -e "s/<profile-name>/ultra/g" \
  -e "s/<p50_ms>/$p50_ms/g" \
  -e "s/<p95_ms>/$p95_ms/g" \
  -e "s/<bytes_per_op>/$bytes_per_op/g" \
  -e "s/<allocs_per_op>/$allocs_per_op/g" \
  -e "s/<peak_rss_kb>/$peak_rss_kb/g" \
  "$ROOT/scripts/bench/report-template.md" >"$OUT_DIR/report.md"

cat >>"$OUT_DIR/report.md" <<EOF

## Ultra Speedups

- Synthetic tree adaptive/ultra p50 speedup: \`${synthetic_speedup}x\`
- Sensitive-dense adaptive/ultra p50 speedup: \`${sensitive_speedup}x\`
EOF

echo "[bench-baseline] generated:"
echo "  - $OUT_DIR/benchmark.txt"
echo "  - $OUT_DIR/benchmark-prefilter.txt"
echo "  - $OUT_DIR/scan-samples.txt"
echo "  - $OUT_DIR/sensitive-samples.txt"
echo "  - $OUT_DIR/report.md"
