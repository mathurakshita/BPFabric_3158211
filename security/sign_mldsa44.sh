#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <elf-object>"
    exit 1
fi

OBJECT_FILE="$1"
PRIVATE_KEY="security/oqs/mldsa44_private.key"
SIGNATURE_FILE="${OBJECT_FILE}.mldsa44.sig"

openssl pkeyutl \
  -provider default \
  -provider oqsprovider \
  -sign \
  -inkey "$PRIVATE_KEY" \
  -rawin \
  -in "$OBJECT_FILE" \
  -out "$SIGNATURE_FILE"

echo "Signed $OBJECT_FILE"
echo "Signature: $SIGNATURE_FILE"
