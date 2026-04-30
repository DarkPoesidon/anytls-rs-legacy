#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT="$OUT_DIR/selfsigned.crt"
KEY="$OUT_DIR/selfsigned.key"

echo "Generating self-signed certificate and key in $OUT_DIR"
echo "Certificate: $CERT"
echo "Key: $KEY"

openssl req -x509 -nodes -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 3650 -subj "/CN=localhost"

echo "Generation complete"
