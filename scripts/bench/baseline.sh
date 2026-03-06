#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/artifacts/bench/$(date -u +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"

echo "[bench-baseline] output directory: $OUT_DIR"

pushd "$ROOT/src" >/dev/null
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench \
  'BenchmarkCollectFileData|BenchmarkScanFilesSyntheticTree|BenchmarkScanFilesCorpora|BenchmarkDeltaSecondRunCorpora|BenchmarkTraversal(Deep|Wide)Tree|BenchmarkLooksLikeTextFast|BenchmarkChunkSource|BenchmarkStreamAho|BenchmarkWriterQueue|BenchmarkDeltaChunkCache' \
  -benchmem ./scanner | tee "$OUT_DIR/benchmark.txt"
go test -run '^$' -bench 'BenchmarkTokenContains' -benchmem ./scanner/prefilter \
  | tee "$OUT_DIR/benchmark-prefilter.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench \
  '^BenchmarkCollectFileData/(build-modules-per-call|reuse-prebuilt-modules)$' \
  -benchmem -count=9 ./scanner | tee "$OUT_DIR/collect-file-data-samples.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench '^BenchmarkScanFilesSyntheticTree/(adaptive|ultra)$' \
  -benchmem -count=9 ./scanner | tee "$OUT_DIR/scan-samples.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench \
  '^BenchmarkScanFilesCorpora/sensitive_dense/(adaptive|ultra)$' -benchmem -count=9 ./scanner \
  | tee "$OUT_DIR/sensitive-samples.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench \
  '^BenchmarkScanFilesCorpora/small_files/(adaptive|ultra)$' -benchmem -count=9 ./scanner \
  | tee "$OUT_DIR/small-files-samples.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench \
  '^BenchmarkScanFilesCorpora/mixed_heavy_tail/(adaptive|ultra)$' -benchmem -count=9 ./scanner \
  | tee "$OUT_DIR/mixed-heavy-tail-samples.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench \
  '^BenchmarkScanFilesCorpora/duplicate_logs/(adaptive|ultra)$' -benchmem -count=9 ./scanner \
  | tee "$OUT_DIR/duplicate-logs-samples.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench \
  '^BenchmarkDeltaSecondRunCorpora/duplicate_logs/(adaptive|ultra)$' -benchmem -count=9 ./scanner \
  | tee "$OUT_DIR/delta-second-run-samples.txt"
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench \
  '^BenchmarkDeltaSecondRunCorpora/duplicate_logs/(mtime|chunk)$' -benchmem -count=9 ./scanner \
  | tee "$OUT_DIR/delta-cache-mode-samples.txt"
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
mapfile -t ultra_small_files_samples < <(extract_samples "$OUT_DIR/small-files-samples.txt" \
  "BenchmarkScanFilesCorpora/small_files/ultra" "ns/op")
mapfile -t adaptive_small_files_samples < <(extract_samples "$OUT_DIR/small-files-samples.txt" \
  "BenchmarkScanFilesCorpora/small_files/adaptive" "ns/op")
mapfile -t ultra_mixed_heavy_tail_samples < <(extract_samples "$OUT_DIR/mixed-heavy-tail-samples.txt" \
  "BenchmarkScanFilesCorpora/mixed_heavy_tail/ultra" "ns/op")
mapfile -t adaptive_mixed_heavy_tail_samples < <(extract_samples "$OUT_DIR/mixed-heavy-tail-samples.txt" \
  "BenchmarkScanFilesCorpora/mixed_heavy_tail/adaptive" "ns/op")
mapfile -t ultra_duplicate_logs_samples < <(extract_samples "$OUT_DIR/duplicate-logs-samples.txt" \
  "BenchmarkScanFilesCorpora/duplicate_logs/ultra" "ns/op")
mapfile -t adaptive_duplicate_logs_samples < <(extract_samples "$OUT_DIR/duplicate-logs-samples.txt" \
  "BenchmarkScanFilesCorpora/duplicate_logs/adaptive" "ns/op")
mapfile -t ultra_delta_second_run_samples < <(extract_samples "$OUT_DIR/delta-second-run-samples.txt" \
  "BenchmarkDeltaSecondRunCorpora/duplicate_logs/ultra" "ns/op")
mapfile -t adaptive_delta_second_run_samples < <(extract_samples "$OUT_DIR/delta-second-run-samples.txt" \
  "BenchmarkDeltaSecondRunCorpora/duplicate_logs/adaptive" "ns/op")
mapfile -t chunk_delta_second_run_samples < <(extract_samples "$OUT_DIR/delta-cache-mode-samples.txt" \
  "BenchmarkDeltaSecondRunCorpora/duplicate_logs/chunk" "ns/op")
mapfile -t mtime_delta_second_run_samples < <(extract_samples "$OUT_DIR/delta-cache-mode-samples.txt" \
  "BenchmarkDeltaSecondRunCorpora/duplicate_logs/mtime" "ns/op")

synthetic_p50_ms="$(median_ms "${ultra_ns_samples[@]}")"
synthetic_p95_ms="$(percentile_ms "${ultra_ns_samples[@]}")"
sensitive_dense_p50_ms="$(median_ms "${ultra_sensitive_samples[@]}")"
small_files_p50_ms="$(median_ms "${ultra_small_files_samples[@]}")"
mixed_heavy_tail_p50_ms="$(median_ms "${ultra_mixed_heavy_tail_samples[@]}")"
duplicate_logs_p50_ms="$(median_ms "${ultra_duplicate_logs_samples[@]}")"
delta_second_run_p50_ms="$(median_ms "${ultra_delta_second_run_samples[@]}")"

synthetic_bytes_per_op="$(awk '/BenchmarkScanFilesSyntheticTree\/ultra/ {
  for (i = 1; i <= NF; i++) if ($i == "B/op") value=$(i-1)
} END {
  if (value != "") print value; else print "n/a"
}' "$OUT_DIR/scan-samples.txt")"

synthetic_allocs_per_op="$(awk '/BenchmarkScanFilesSyntheticTree\/ultra/ {
  for (i = 1; i <= NF; i++) if ($i == "allocs/op") value=$(i-1)
} END {
  if (value != "") print value; else print "n/a"
}' "$OUT_DIR/scan-samples.txt")"

synthetic_speedup="n/a"
sensitive_speedup="n/a"
small_files_speedup="n/a"
mixed_heavy_tail_speedup="n/a"
duplicate_logs_speedup="n/a"
delta_second_run_speedup="n/a"
delta_cache_mode_speedup="n/a"
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
if (( ${#adaptive_small_files_samples[@]} > 0 && ${#ultra_small_files_samples[@]} > 0 )); then
  adaptive_small_files_median="${adaptive_small_files_samples[$(( (${#adaptive_small_files_samples[@]} - 1) / 2 ))]}"
  ultra_small_files_median="${ultra_small_files_samples[$(( (${#ultra_small_files_samples[@]} - 1) / 2 ))]}"
  small_files_speedup="$(ratio "$adaptive_small_files_median" "$ultra_small_files_median")"
fi
if (( ${#adaptive_mixed_heavy_tail_samples[@]} > 0 && ${#ultra_mixed_heavy_tail_samples[@]} > 0 )); then
  adaptive_mixed_heavy_tail_median="${adaptive_mixed_heavy_tail_samples[$(( (${#adaptive_mixed_heavy_tail_samples[@]} - 1) / 2 ))]}"
  ultra_mixed_heavy_tail_median="${ultra_mixed_heavy_tail_samples[$(( (${#ultra_mixed_heavy_tail_samples[@]} - 1) / 2 ))]}"
  mixed_heavy_tail_speedup="$(ratio "$adaptive_mixed_heavy_tail_median" "$ultra_mixed_heavy_tail_median")"
fi
if (( ${#adaptive_duplicate_logs_samples[@]} > 0 && ${#ultra_duplicate_logs_samples[@]} > 0 )); then
  adaptive_duplicate_logs_median="${adaptive_duplicate_logs_samples[$(( (${#adaptive_duplicate_logs_samples[@]} - 1) / 2 ))]}"
  ultra_duplicate_logs_median="${ultra_duplicate_logs_samples[$(( (${#ultra_duplicate_logs_samples[@]} - 1) / 2 ))]}"
  duplicate_logs_speedup="$(ratio "$adaptive_duplicate_logs_median" "$ultra_duplicate_logs_median")"
fi
if (( ${#adaptive_delta_second_run_samples[@]} > 0 && ${#ultra_delta_second_run_samples[@]} > 0 )); then
  adaptive_delta_second_run_median="${adaptive_delta_second_run_samples[$(( (${#adaptive_delta_second_run_samples[@]} - 1) / 2 ))]}"
  ultra_delta_second_run_median="${ultra_delta_second_run_samples[$(( (${#ultra_delta_second_run_samples[@]} - 1) / 2 ))]}"
  delta_second_run_speedup="$(ratio "$adaptive_delta_second_run_median" "$ultra_delta_second_run_median")"
fi
if (( ${#mtime_delta_second_run_samples[@]} > 0 && ${#chunk_delta_second_run_samples[@]} > 0 )); then
  mtime_delta_second_run_median="${mtime_delta_second_run_samples[$(( (${#mtime_delta_second_run_samples[@]} - 1) / 2 ))]}"
  chunk_delta_second_run_median="${chunk_delta_second_run_samples[$(( (${#chunk_delta_second_run_samples[@]} - 1) / 2 ))]}"
  delta_cache_mode_speedup="$(ratio "$mtime_delta_second_run_median" "$chunk_delta_second_run_median")"
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
  -e "s/<synthetic_p50_ms>/$synthetic_p50_ms/g" \
  -e "s/<synthetic_p95_ms>/$synthetic_p95_ms/g" \
  -e "s/<synthetic_bytes_per_op>/$synthetic_bytes_per_op/g" \
  -e "s/<synthetic_allocs_per_op>/$synthetic_allocs_per_op/g" \
  -e "s/<sensitive_dense_p50_ms>/$sensitive_dense_p50_ms/g" \
  -e "s/<small_files_p50_ms>/$small_files_p50_ms/g" \
  -e "s/<mixed_heavy_tail_p50_ms>/$mixed_heavy_tail_p50_ms/g" \
  -e "s/<duplicate_logs_p50_ms>/$duplicate_logs_p50_ms/g" \
  -e "s/<delta_second_run_p50_ms>/$delta_second_run_p50_ms/g" \
  -e "s/<peak_rss_kb>/$peak_rss_kb/g" \
  "$ROOT/scripts/bench/report-template.md" >"$OUT_DIR/report.md"

cat >>"$OUT_DIR/report.md" <<EOF

## Ultra Speedups

- Synthetic tree adaptive/ultra p50 speedup: \`${synthetic_speedup}x\`
- Sensitive-dense adaptive/ultra p50 speedup: \`${sensitive_speedup}x\`
- Small-files adaptive/ultra p50 speedup: \`${small_files_speedup}x\`
- Mixed-heavy-tail adaptive/ultra p50 speedup: \`${mixed_heavy_tail_speedup}x\`
- Duplicate-logs adaptive/ultra p50 speedup: \`${duplicate_logs_speedup}x\`
- Delta second-run adaptive/ultra p50 speedup: \`${delta_second_run_speedup}x\`
- Delta second-run chunk/mtime p50 speedup: \`${delta_cache_mode_speedup}x\`
EOF

echo "[bench-baseline] generated:"
echo "  - $OUT_DIR/benchmark.txt"
echo "  - $OUT_DIR/benchmark-prefilter.txt"
echo "  - $OUT_DIR/collect-file-data-samples.txt"
echo "  - $OUT_DIR/scan-samples.txt"
echo "  - $OUT_DIR/sensitive-samples.txt"
echo "  - $OUT_DIR/small-files-samples.txt"
echo "  - $OUT_DIR/mixed-heavy-tail-samples.txt"
echo "  - $OUT_DIR/duplicate-logs-samples.txt"
echo "  - $OUT_DIR/delta-second-run-samples.txt"
echo "  - $OUT_DIR/delta-cache-mode-samples.txt"
echo "  - $OUT_DIR/report.md"
