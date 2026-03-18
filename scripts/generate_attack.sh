#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"

echo "Generating suspicious web traffic against $BASE_URL"

for i in {1..3}; do
  curl -sk -A "Mozilla/5.0" -o /dev/null "$BASE_URL/"
done

for i in {1..8}; do
  curl -sk -A "sqlmap/1.8" -o /dev/null "$BASE_URL/.env"
done

for i in {1..12}; do
  curl -sk -A "Mozilla/5.0" -o /dev/null "$BASE_URL/wp-login.php?user=admin"
done

for i in {1..6}; do
  curl -sk -A "Nmap Scripting Engine" -o /dev/null "$BASE_URL/server-status"
done

for i in {1..6}; do
  curl -sk -A "Mozilla/5.0" -o /dev/null "$BASE_URL/admin"
done

echo "HTTP attack simulation complete. Check Grafana Explore and detector logs."
