#!/bin/bash

# Integration test runner script for cpworker
# Usage: ./run_test.sh <test_case_name|all>
# Example: ./run_test.sh case2_vxlan_basic
# Example: ./run_test.sh testdata/cases/case2_vxlan_basic
# Example: ./run_test.sh all

set -e

# Parse test case name
if [ $# -eq 0 ]; then
    echo "Usage: $0 <test_case_name|all>"
    echo "Example: $0 case2_vxlan_basic"
    echo "Example: $0 testdata/cases/case2_vxlan_basic"
    echo "Example: $0 all"
    echo ""
    echo "Available test cases:"
    ls -1 testdata/cases/ 2>/dev/null | grep -v README.md || echo "  No test cases found"
    exit 1
fi

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Configuration
# 1. Get current user's LD_LIBRARY_PATH (to be passed to sudo)
ENV_LD_LIBRARY_PATH="${LD_LIBRARY_PATH}"

# 2. Get go binary path
GO_BIN=$(command -v go)
if [ -z "$GO_BIN" ]; then
    echo "ERROR: 'go' binary not found in PATH."
    exit 1
fi

# 3. Resolve CPWORKER_BIN relative to project root
CPWORKER_BIN="${PROJECT_ROOT}/build/dist/linux-amd64/cloud-probe/bin/cpworker"

# Check if cpworker binary exists
if [ ! -f "$CPWORKER_BIN" ]; then
    echo "ERROR: cpworker binary not found at $CPWORKER_BIN"
    echo "Please build cpworker first:"
    echo "  cd build && go run mage.go cpworker:linux"
    exit 1
fi

# Save current user for chown later
CURRENT_USER=$(whoami)
CURRENT_UID=$(id -u)
CURRENT_GID=$(id -g)

# Check if running all tests
if [ "$1" = "all" ]; then
    echo "========================================="
    echo "cpworker Integration Test Runner"
    echo "========================================="
    echo "Mode: Running ALL test cases"
    echo "cpworker Binary: $CPWORKER_BIN"
    echo "Running as: $CURRENT_USER (will use sudo for packet capture)"
    echo "========================================="
    echo ""

    # Run all tests with sudo
    echo "Running all tests with sudo (required for packet capture)..."
    sudo -E CPWORKER_BIN="$CPWORKER_BIN" \
         LD_LIBRARY_PATH="$ENV_LD_LIBRARY_PATH" \
         "$GO_BIN" test -v -run "TestIntegration"

    TEST_EXIT_CODE=$?

    # Change ownership of entire output directory back to current user
    OUTPUT_BASE_DIR="testdata/output"
    if [ -d "$OUTPUT_BASE_DIR" ]; then
        echo ""
        echo "Changing ownership of all output files to $CURRENT_USER..."
        sudo chown -R "$CURRENT_UID:$CURRENT_GID" "$OUTPUT_BASE_DIR"
        echo "Output directory: $OUTPUT_BASE_DIR"
        echo ""
        echo "Test case outputs:"
        ls -lh "$OUTPUT_BASE_DIR"
    fi

    echo ""
    echo "========================================="
    if [ $TEST_EXIT_CODE -eq 0 ]; then
        echo "All tests PASSED!"
    else
        echo "Some tests FAILED!"
    fi
    echo "========================================="

    exit $TEST_EXIT_CODE
fi

# Extract test case name (remove testdata/cases/ prefix if present)
TEST_CASE="$1"
TEST_CASE="${TEST_CASE#testdata/cases/}"
TEST_CASE="${TEST_CASE%/}"

echo "========================================="
echo "cpworker Integration Test Runner"
echo "========================================="
echo "Test Case: $TEST_CASE"
echo "cpworker Binary: $CPWORKER_BIN"
echo "Running as: $CURRENT_USER (will use sudo for packet capture)"
echo "========================================="
echo ""

# Run the test with sudo
echo "Running test with sudo (required for packet capture)..."
sudo -E CPWORKER_BIN="$CPWORKER_BIN" \
     LD_LIBRARY_PATH="$ENV_LD_LIBRARY_PATH" \
     "$GO_BIN" test -v -run "TestIntegration/$TEST_CASE"

TEST_EXIT_CODE=$?

# Change ownership of output files back to current user
OUTPUT_DIR="testdata/output/$TEST_CASE"
if [ -d "$OUTPUT_DIR" ]; then
    echo ""
    echo "Changing ownership of output files to $CURRENT_USER..."
    sudo chown -R "$CURRENT_UID:$CURRENT_GID" "$OUTPUT_DIR"
    echo "Output directory: $OUTPUT_DIR"
    echo ""
    echo "Output files:"
    ls -lh "$OUTPUT_DIR"
fi

echo ""
echo "========================================="
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "Test PASSED!"
else
    echo "Test FAILED!"
fi
echo "========================================="

exit $TEST_EXIT_CODE
