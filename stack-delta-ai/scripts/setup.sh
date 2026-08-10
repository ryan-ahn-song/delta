#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

python3 -m venv .venv
.venv/bin/python -m pip install --no-deps -e .
mkdir -p data reports

printf '%s\n' "Ready. Run: $project_dir/.venv/bin/stack-delta serve"

