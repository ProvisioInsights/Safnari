#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/artifacts/bench/simd-$(date -u +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"

pushd "$ROOT/src" >/dev/null
go test -run '^$' -bench 'BenchmarkLooksLikeTextFast|BenchmarkTokenContains' -benchtime=200ms -count=1 -benchmem ./scanner ./scanner/prefilter \
  | tee "$OUT_DIR/generic.txt"
GOEXPERIMENT=simd go test -tags simd -run '^$' -bench 'BenchmarkLooksLikeTextFast|BenchmarkTokenContains' -benchtime=200ms -count=1 -benchmem ./scanner ./scanner/prefilter \
  | tee "$OUT_DIR/simd.txt"
popd >/dev/null

"$ROOT/scripts/bench/compare.sh" "$OUT_DIR/generic.txt" "$OUT_DIR/simd.txt" "$OUT_DIR/benchstat.txt"
echo "[bench-simd] wrote $OUT_DIR/benchstat.txt"
