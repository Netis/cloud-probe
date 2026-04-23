#!/usr/bin/env bash
# ==============================================================================
# Dev — build / test / clean / sync / shell on the configured BUILD_MODE
# ==============================================================================
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/common.sh"

show_help() {
    cat <<EOF

  🚀 Dev — build/test on BUILD_MODE=${BUILD_MODE}

  just dev build [target]    Build (default: all)
                               targets: cpworker | cpctl | cpdaemon | dockerpid | all
  just dev test  [suite]     Test (default: all)
                               suites:  c | go | all
  just dev clean             Wipe build artifacts on the build host
  just dev sync              rsync src → remote (no-op for local/orb)
  just dev shell             Open shell in the build env

  Backend: ${BUILD_MODE}
  Library: ${CPWORKER_LIBRARY_ROOT}
  Version: ${CLOUD_PROBE_VERSION}

EOF
}

cmd_build() {
    local target="${1:-all}"
    local mage_target
    case "$target" in
        all)       mage_target="build:linux" ;;
        cpworker)  mage_target="cpworker:linux" ;;
        cpctl)     mage_target="cpctl:linux" ;;
        cpdaemon)  mage_target="cpdaemon:linux" ;;
        dockerpid) mage_target="dockerpid:linux" ;;
        *) echo -e "${RED}Unknown build target: $target${NC}"; exit 1 ;;
    esac
    run_on_buildhost "cd build && go run mage.go $mage_target"
    if [[ "$BUILD_MODE" != "ssh" ]]; then
        echo -e "${GREEN}✓ build complete: $PROJECT_ROOT/build/dist/linux-amd64/cloud-probe/bin/${NC}"
    else
        echo -e "${GREEN}✓ build complete on ${BUILD_SSH_HOST}:${BUILD_REMOTE_DIR}/build/dist/linux-amd64/cloud-probe/bin/${NC}"
    fi
}

cmd_test() {
    local suite="${1:-all}"
    case "$suite" in
        c)
            run_on_buildhost "cd build/tmp/cpworker-linux-amd64 && make test"
            ;;
        go)
            run_on_buildhost "cd cpgolib && go test ./... && cd ../cpctl && go test ./..."
            ;;
        all)
            run_on_buildhost "(cd build/tmp/cpworker-linux-amd64 && make test) && (cd cpgolib && go test ./...) && (cd cpctl && go test ./...)"
            ;;
        *) echo -e "${RED}Unknown test suite: $suite${NC}"; exit 1 ;;
    esac
}

cmd_clean() {
    run_on_buildhost "cd build && go run mage.go clean"
}

cmd_sync() {
    case "$BUILD_MODE" in
        ssh)   run_rsync; echo -e "${GREEN}✓ synced${NC}" ;;
        local) echo "${YELLOW}sync is a no-op for BUILD_MODE=local${NC}" ;;
        orb)   echo "${YELLOW}sync is a no-op for BUILD_MODE=orb (shared filesystem)${NC}" ;;
    esac
}

cmd_shell() {
    shell_on_buildhost
}

case "${1:-help}" in
    build) shift; cmd_build "$@" ;;
    test)  shift; cmd_test "$@" ;;
    clean) cmd_clean ;;
    sync)  cmd_sync ;;
    shell) cmd_shell ;;
    help|--help|-h|"") show_help ;;
    *) echo -e "${RED}Unknown: dev $1${NC}"; show_help; exit 1 ;;
esac
