#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export EXPERIMENT_MODE=cutter
exec "${SCRIPT_DIR}/run_baseline_once.sh" "$@"
