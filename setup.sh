#!/bin/bash
set -euo pipefail

show_help() {
  cat <<EOF
Usage:
  ./setup.sh <domain>
  DOMAIN_NAME=<domain> ./setup.sh

Examples:
  ./setup.sh example.com
  DOMAIN_NAME=example.com ./setup.sh
EOF
}

DOMAIN_NAME="${1:-${DOMAIN_NAME:-}}"

if [ -z "$DOMAIN_NAME" ]; then
  echo "Error: Domain name is required"
  show_help
  exit 1
fi

BASE_URL="https://${DOMAIN_NAME}"

echo "Setting up Caddy with domain: $DOMAIN_NAME"

ENV_FILE=".env"
touch "$ENV_FILE"

set_env_var() {
  local key="$1"
  local value="$2"

  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed -i.bak "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

set_env_var "DOMAIN_NAME" "$DOMAIN_NAME"
set_env_var "BASE_URL" "$BASE_URL"

rm -f "${ENV_FILE}.bak"

echo "Updated .env:"
grep -E '^(DOMAIN_NAME|BASE_URL)=' "$ENV_FILE"


docker compose -f docker-compose.yml up -d --build
