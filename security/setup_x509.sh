#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CA_DIR="$ROOT_DIR/security/ca"
SIGNER_DIR="$ROOT_DIR/security/signer"

CA_KEY="$CA_DIR/ca_private.key"
CA_CERT="$CA_DIR/ca_cert.pem"

SIGNER_KEY="$SIGNER_DIR/signer_private.key"
SIGNER_CSR="$SIGNER_DIR/signer.csr"
SIGNER_CERT="$SIGNER_DIR/signer_cert.pem"

mkdir -p "$CA_DIR" "$SIGNER_DIR"

echo "[1/5] Generating CA private key..."
openssl genpkey -algorithm ed25519 -out "$CA_KEY"

echo "[2/5] Creating self-signed CA certificate..."
openssl req -x509 -new -key "$CA_KEY" \
  -out "$CA_CERT" \
  -days 3650 \
  -subj "/CN=BPFabric MSc Root CA"

echo "[3/5] Generating signer private key..."
openssl genpkey -algorithm ed25519 -out "$SIGNER_KEY"

echo "[4/5] Creating signer certificate request..."
openssl req -new -key "$SIGNER_KEY" \
  -out "$SIGNER_CSR" \
  -subj "/CN=BPFabric Object Signer"

echo "[5/5] Signing signer certificate with CA..."
openssl x509 -req \
  -in "$SIGNER_CSR" \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -out "$SIGNER_CERT" \
  -days 365

echo
echo "Verifying signer certificate..."
openssl verify -CAfile "$CA_CERT" "$SIGNER_CERT"

echo
echo "X.509 setup complete."
echo "CA certificate:      $CA_CERT"
echo "Signer certificate:  $SIGNER_CERT"
echo "Signer private key:  $SIGNER_KEY"
echo
echo "Important: do not commit private keys to GitHub."
