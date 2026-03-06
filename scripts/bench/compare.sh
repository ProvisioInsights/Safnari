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
  if [[ ! -d "$BASELINE" ]]; then
    echo "baseline file or directory not found: $BASELINE" >&2
    exit 1
  fi
fi
if [[ ! -f "$CANDIDATE" ]]; then
  if [[ ! -d "$CANDIDATE" ]]; then
    echo "candidate file or directory not found: $CANDIDATE" >&2
    exit 1
  fi
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
  if [[ -d "$BASELINE" || -d "$CANDIDATE" ]]; then
    mapfile -t baseline_inputs < <(find "$BASELINE" -maxdepth 1 -type f -name '*.txt' | sort)
    mapfile -t candidate_inputs < <(find "$CANDIDATE" -maxdepth 1 -type f -name '*.txt' | sort)
    "$BENCHSTAT_BIN" "${baseline_inputs[@]}" "${candidate_inputs[@]}" | tee "$OUT_FILE"
  else
    "$BENCHSTAT_BIN" "$BASELINE" "$CANDIDATE" | tee "$OUT_FILE"
  fi
  echo "[bench-compare] wrote comparison to $OUT_FILE"
else
  if [[ -d "$BASELINE" || -d "$CANDIDATE" ]]; then
    mapfile -t baseline_inputs < <(find "$BASELINE" -maxdepth 1 -type f -name '*.txt' | sort)
    mapfile -t candidate_inputs < <(find "$CANDIDATE" -maxdepth 1 -type f -name '*.txt' | sort)
    "$BENCHSTAT_BIN" "${baseline_inputs[@]}" "${candidate_inputs[@]}"
  else
    "$BENCHSTAT_BIN" "$BASELINE" "$CANDIDATE"
  fi
fi
