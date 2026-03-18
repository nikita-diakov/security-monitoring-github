#!/usr/bin/env bash
set -euo pipefail

./scripts/init.sh
docker compose up -d --build

echo "Stack started."
echo "Nginx demo:   http://localhost:8080"
echo "Grafana:      http://localhost:3000"
echo "Loki API:     http://localhost:3100/ready"
echo "Alloy UI:     http://localhost:12345"
