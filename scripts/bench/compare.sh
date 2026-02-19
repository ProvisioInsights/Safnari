#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 <baseline-benchmark.txt> <candidate-benchmark.txt> [output-file]" >&2
  exit 1
fi

BASELINE="$1"
CANDIDATE="$2"
OUT_FILE="${3:-}"

if [[ ! -f "$BASELINE" ]]; then
  echo "baseline file not found: $BASELINE" >&2
  exit 1
fi
if [[ ! -f "$CANDIDATE" ]]; then
  echo "candidate file not found: $CANDIDATE" >&2
  exit 1
fi

if ! command -v benchstat >/dev/null 2>&1; then
  echo "[bench-compare] benchstat not found; installing golang.org/x/perf/cmd/benchstat@latest"
  go install golang.org/x/perf/cmd/benchstat@latest
fi

BENCHSTAT_BIN="$(go env GOPATH)/bin/benchstat"
if [[ ! -x "$BENCHSTAT_BIN" ]]; then
  BENCHSTAT_BIN="$(command -v benchstat)"
fi

if [[ -n "$OUT_FILE" ]]; then
  "$BENCHSTAT_BIN" "$BASELINE" "$CANDIDATE" | tee "$OUT_FILE"
  echo "[bench-compare] wrote comparison to $OUT_FILE"
else
  "$BENCHSTAT_BIN" "$BASELINE" "$CANDIDATE"
fi

