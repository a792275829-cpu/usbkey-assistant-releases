#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TLS_DIR="$PROJECT_DIR/.local/tls"

mkdir -p "$TLS_DIR"
/usr/bin/openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout "$TLS_DIR/localhost.key" \
  -out "$TLS_DIR/localhost.crt" \
  -days 3650 \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"
chmod 600 "$TLS_DIR/localhost.key"

echo "Created $TLS_DIR/localhost.crt"
echo "Created $TLS_DIR/localhost.key"
echo "Trust of the certificate must be confirmed by the user in Keychain Access."
