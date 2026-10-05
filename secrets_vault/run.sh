#!/usr/bin/env bash
set -euo pipefail
make
exec ./bin/secrets_vault "${1:-./data}"
