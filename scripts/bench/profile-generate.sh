#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROFILE_PATH="${1:-$ROOT/src/pgo/default.pgo}"
if [[ "$PROFILE_PATH" != /* ]]; then
  PROFILE_PATH="$ROOT/$PROFILE_PATH"
fi

mkdir -p "$(dirname "$PROFILE_PATH")"
echo "[profile-generate] writing profile: $PROFILE_PATH"

pushd "$ROOT/src" >/dev/null
SAFNARI_DISABLE_PROGRESS=1 go test -run '^$' -bench \
  'BenchmarkScanFilesSyntheticTree/ultra$|BenchmarkScanFilesCorpora/(mixed|sensitive_dense|large_files)/ultra$' \
  -benchtime=5x -count=1 -cpuprofile "$PROFILE_PATH" ./scanner
popd >/dev/null

echo "[profile-generate] done"
