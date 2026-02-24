#!/bin/bash
# VANTABLACK Performance Profiling Script

set -e

APP_NAME=$1
OUTPUT_FILE=$2

if [ -z "$APP_NAME" ]; then
  echo "Usage: ./profile.sh <app_name> [output_file.svg]"
  echo "Example: ./profile.sh rest_api profile.svg"
  exit 1
fi

if [ -z "$OUTPUT_FILE" ]; then
  OUTPUT_FILE="profile_$(date +%s).svg"
fi

# Find the PID of the uvicorn process for the specified app
# We search for the file path to be specific
PID=$(pgrep -f "uvicorn.*$APP_NAME")

if [ -z "$PID" ]; then
  echo "Error: Could not find running process for '$APP_NAME'."
  echo "Is the application running?"
  exit 1
fi

# Check if py-spy is installed
if ! command -v py-spy &> /dev/null
then
    echo "Error: py-spy is not installed. Please run 'pip install py-spy'"
    exit 1
fi

echo "Found $APP_NAME process with PID: $PID"
echo "Profiling for 30 seconds... Output will be saved to $OUTPUT_FILE"

# Run py-spy and generate a flame graph
sudo py-spy record -p $PID -o $OUTPUT_FILE -d 30 --native

echo "Profiling complete. Flame graph saved to $OUTPUT_FILE"
