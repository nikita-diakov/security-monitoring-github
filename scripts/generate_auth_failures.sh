#!/usr/bin/env bash
set -euo pipefail

TARGET_FILE="${1:-./logs/auth.log}"
mkdir -p "$(dirname "$TARGET_FILE")"
touch "$TARGET_FILE"

echo "Writing fake SSH failures to $TARGET_FILE"

for user in admin root oracle postgres test; do
  for i in {1..2}; do
    printf "%s ubuntu sshd[%s]: Failed password for invalid user %s from 203.0.113.50 port %s ssh2\n" \
      "$(date '+%b %e %T')" "$RANDOM" "$user" "$((10000 + RANDOM % 50000))" >> "$TARGET_FILE"
    sleep 0.2
  done
done

echo "Fake SSH failures written."
