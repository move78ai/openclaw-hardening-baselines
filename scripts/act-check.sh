#!/usr/bin/env bash
set -euo pipefail

OUT="act-check.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUT="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

python3 "$(dirname "$0")/act-check.py" --output "$OUT"
echo "Wrote: $OUT"
