#!/bin/bash

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Rebuild before running
echo "Building cpworker..."
cd "${PROJECT_ROOT}/build"
go run mage.go clean
go run mage.go cpworker:linux
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to build cpworker."
    exit 1
fi
echo "Build successful."