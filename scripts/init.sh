#!/usr/bin/env bash
set -euo pipefail

mkdir -p logs/nginx alerts
: > logs/auth.log
: > logs/nginx/access.log
: > logs/nginx/error.log
: > alerts/alerts.jsonl

echo "Initialized local log files."
