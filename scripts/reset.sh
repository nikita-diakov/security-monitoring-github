#!/usr/bin/env bash
set -euo pipefail

docker compose down
./scripts/init.sh

echo "Lab reset complete."
