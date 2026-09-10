#!/bin/bash
#
# Integration test runner for cpworker.
#
# Usage: ./run_test.sh <test_case_name|all|reload>
#   all               Run every test in this module.
#   reload            Run TestReload only (config reload, rtc & pipeline).
#   vxlan_basic       Run a single integration test case.
#   testdata/cases/…  Equivalent to the case name form.

set -e

# ─── Resolve environment and paths ──────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$SCRIPT_DIR"

USER_LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}"
USER_PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-}"

GO_BIN="$(command -v go || true)"
if [ -z "$GO_BIN" ]; then
    echo "ERROR: 'go' binary not found in PATH."
    exit 1
fi

case "$(uname -m)" in
    x86_64)        DEFAULT_ARCH="amd64" ;;
    aarch64|arm64) DEFAULT_ARCH="arm64" ;;
    *)
        echo "ERROR: unsupported host architecture: $(uname -m)"
        exit 1
        ;;
esac

ARCH="${CPWORKER_ARCH:-$DEFAULT_ARCH}"
CPWORKER_BIN="${CPWORKER_BIN:-$PROJECT_ROOT/build/dist/linux-$ARCH/cloud-probe/bin/cpworker}"
case "$CPWORKER_BIN" in
    /*) ;;
    *)  CPWORKER_BIN="$PWD/${CPWORKER_BIN#./}" ;;
esac

if [ ! -x "$CPWORKER_BIN" ]; then
    echo "ERROR: cpworker binary not found at $CPWORKER_BIN"
    echo "Please build cpworker first:"
    echo "  cd build && go run mage.go cpworker:linux"
    exit 1
fi

CURRENT_USER=$(whoami)
CURRENT_UID=$(id -u)
CURRENT_GID=$(id -g)

# Packet capture requires CAP_NET_RAW. Run without sudo when already root
# (for example, in a CI container); otherwise use sudo.
SUDO_CMD=()
if [ "$CURRENT_UID" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: 'sudo' is required for packet capture when not running as root."
        exit 1
    fi
    SUDO_CMD=(sudo)
fi

# ─── Helper functions ────────────────────────────────────────────────────────

restore_ownership() {
    local dir="$1"
    if [ -d "$dir" ] && [ "${#SUDO_CMD[@]}" -gt 0 ]; then
        sudo chown -R "$CURRENT_UID:$CURRENT_GID" "$dir" || true
    fi
}

# Run go tests with the resolved cpworker binary and environment.
# Arguments are passed directly to `go test`.
run_tests() {
    set +e
    "${SUDO_CMD[@]}" env \
        CPWORKER_BIN="$CPWORKER_BIN" \
        LD_LIBRARY_PATH="$USER_LD_LIBRARY_PATH" \
        PKG_CONFIG_PATH="$USER_PKG_CONFIG_PATH" \
        "$GO_BIN" test -count=1 -v "$@"
    TEST_EXIT_CODE=$?
    set -e
}

# Print the pass/fail summary, restore output ownership, and exit.
finish() {
    local output_dir="$1" label="$2"
    restore_ownership "$output_dir"
    echo ""
    echo "========================================="
    if [ "$TEST_EXIT_CODE" -eq 0 ]; then
        echo "$label PASSED!"
    else
        echo "$label FAILED!"
    fi
    echo "========================================="
    if [ -d "$output_dir" ]; then
        echo ""
        echo "Output directory: $output_dir"
        echo "Output files:"
        ls -lh "$output_dir"
    fi
    exit "$TEST_EXIT_CODE"
}

usage() {
    echo "Usage: $0 <test_case_name|all|reload>"
    echo "Example: $0 vxlan_basic"
    echo "Example: $0 testdata/cases/vxlan_basic"
    echo "Example: $0 all"
    echo "Example: $0 reload"
    echo ""
    echo "Available test cases:"
    ls -1 testdata/cases/ 2>/dev/null | grep -v README.md || echo "  No test cases found"
    echo ""
    echo "Special targets:"
    echo "  all     (runs every test in this module)"
    echo "  reload  (runs TestReload only: config reload, rtc & pipeline)"
    exit 1
}

# ─── Main dispatch ───────────────────────────────────────────────────────────

if [ $# -eq 0 ]; then
    usage
fi

echo "========================================="
echo "cpworker Integration Test Runner"
echo "========================================="
echo "cpworker Binary: $CPWORKER_BIN"
echo "Running as: $CURRENT_USER (packet capture requires CAP_NET_RAW)"
echo "========================================="
echo ""

case "$1" in
    all)
        echo "Mode: Running ALL test cases"
        echo "Running all tests..."
        OUTPUT_DIR="$SCRIPT_DIR/testdata/output"
        trap 'restore_ownership "$OUTPUT_DIR"' EXIT
        run_tests ./...
        finish "$OUTPUT_DIR" "All tests"
        ;;
    reload)
        echo "Mode: Running TestReload (config reload)"
        echo "Running TestReload..."
        OUTPUT_DIR="$SCRIPT_DIR/testdata/output/reload"
        trap 'restore_ownership "$OUTPUT_DIR"' EXIT
        run_tests -run "TestReload"
        finish "$OUTPUT_DIR" "Test"
        ;;
    *)
        TEST_CASE="${1#testdata/cases/}"
        TEST_CASE="${TEST_CASE%/}"
        echo "Mode: Running test case: $TEST_CASE"
        echo "Running test..."
        OUTPUT_DIR="$SCRIPT_DIR/testdata/output/$TEST_CASE"
        trap 'restore_ownership "$OUTPUT_DIR"' EXIT
        run_tests -run "TestIntegration/$TEST_CASE"
        finish "$OUTPUT_DIR" "Test"
        ;;
esac
