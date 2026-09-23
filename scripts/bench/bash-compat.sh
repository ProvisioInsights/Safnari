#!/usr/bin/env bash

# macOS still ships Bash 3.2, which lacks mapfile. The benchmark scripts only
# use `mapfile -t array` with newline-delimited input.
if ! type mapfile >/dev/null 2>&1; then
  mapfile() {
    if [[ $# -ne 2 || "$1" != "-t" ]]; then
      echo "mapfile compatibility helper supports only -t <array>" >&2
      return 2
    fi
    local target="$2"
    IFS=$'\n' read -r -d '' -a "$target" < <(cat; printf '\0')
  }
fi
