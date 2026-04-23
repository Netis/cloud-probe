#!/usr/bin/env bash
# ==============================================================================
# Remote — manage the SSH build host (ts@10.40.7.104 by default)
# ==============================================================================
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/common.sh"

show_help() {
    cat <<EOF

  🖥️  Remote build host — ${BUILD_SSH_HOST}

  just remote ping            Test SSH connectivity
  just remote ssh             Interactive SSH (drops you into ${BUILD_REMOTE_DIR})
  just remote info            Show versions + paths on the remote
  just remote setup           One-time: distro deps + Go proxy + SDK skeleton + marker
  just remote install-just    Install just(1) on the remote (~/bin/just)

  Effective config:
    Host:        ${BUILD_SSH_HOST}
    Remote dir:  ${BUILD_REMOTE_DIR}
    SDK root:    ${CPWORKER_LIBRARY_ROOT}
    Root pwd:    $([[ -n "$BUILD_SSH_ROOT_PASSWORD" ]] && echo "(set in .env.local)" || echo "(not set — needed for setup)")

EOF
}

cmd_ping() {
    echo -e "${BLUE}Pinging ${BUILD_SSH_HOST}...${NC}"
    if run_ssh 'echo connected; hostname; whoami; uname -sr'; then
        echo -e "${GREEN}✓ OK${NC}"
    else
        echo -e "${RED}✗ Failed${NC}"; exit 1
    fi
}

cmd_ssh() {
    run_ssh_tty "cd '$BUILD_REMOTE_DIR' 2>/dev/null; exec bash -l"
}

cmd_info() {
    run_ssh "
        echo '─── tools ───'
        for t in go cmake make gcc rsync just; do
            if ! command -v \$t >/dev/null 2>&1; then printf '%-8s (missing)\n' \"\$t:\"; continue; fi
            if [ \"\$t\" = go ]; then v=\$(go version); else v=\$(\$t --version 2>&1 | head -1); fi
            printf '%-8s %s\n' \"\$t:\" \"\$v\"
        done
        echo
        echo '─── env ───'
        echo \"PWD:                 \$(pwd)\"
        echo \"BUILD_REMOTE_DIR:    $BUILD_REMOTE_DIR (\$([ -d $BUILD_REMOTE_DIR ] && echo present || echo missing))\"
        echo \"CPWORKER_LIBRARY_ROOT: $CPWORKER_LIBRARY_ROOT (\$([ -d $CPWORKER_LIBRARY_ROOT ] && echo present || echo missing))\"
        echo \"GOPROXY:             \$(go env GOPROXY 2>/dev/null || echo n/a)\"
        echo \"~/.cpw-buildhost:    \$([ -f ~/.cpw-buildhost ] && echo present || echo missing)\"
    "
}

# ---------------------------------------------------------------------------
# Setup — one-time install of build deps, SDK skeleton, marker file
# ---------------------------------------------------------------------------
cmd_setup() {
    [[ -z "$BUILD_SSH_ROOT_PASSWORD" ]] && {
        echo -e "${RED}BUILD_SSH_ROOT_PASSWORD not set in .env.local — required for apt installs${NC}"
        exit 1
    }

    echo -e "${BLUE}━━ 1/5 install distro packages (as root via su -)${NC}"
    run_ssh_root <<'EOF'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y golang-go cmake pkg-config libpcap-dev libzmq3-dev rsync >/dev/null
echo "installed: $(go version), $(cmake --version | head -1)"
EOF

    echo -e "${BLUE}━━ 2/5 configure Go proxy (proxy.golang.org isn't reachable)${NC}"
    run_ssh "go env -w GOPROXY='$GOPROXY' && echo GOPROXY=\$(go env GOPROXY)"

    echo -e "${BLUE}━━ 3/5 build SDK skeleton at ${CPWORKER_LIBRARY_ROOT}${NC}"
    # CMake hard-codes find_library(ZMQ_LIB libzmq.a ...) but Ubuntu's libzmq.a
    # was built with norm/pgm/sodium/gssapi support whose libs aren't on cpworker's
    # link line — pointing the .a name at the .so makes ld link dynamically.
    run_ssh "
        set -e
        SDK='$CPWORKER_LIBRARY_ROOT'
        rm -rf \$SDK
        mkdir -p \$SDK/include \$SDK/lib
        cp -a /usr/include/pcap.h /usr/include/pcap-bpf.h /usr/include/pcap-namedb.h /usr/include/pcap \$SDK/include/
        cp -a /usr/include/zmq.h /usr/include/zmq_utils.h \$SDK/include/
        ln -sf /usr/lib/x86_64-linux-gnu/libpcap.so   \$SDK/lib/libpcap.so
        ln -sf /usr/lib/x86_64-linux-gnu/libpcap.so.1 \$SDK/lib/libpcap.so.1
        ln -sf /usr/lib/x86_64-linux-gnu/libpcap.a    \$SDK/lib/libpcap.a
        ln -sf /usr/lib/x86_64-linux-gnu/libzmq.so    \$SDK/lib/libzmq.a
        ln -sf /usr/lib/x86_64-linux-gnu/libzmq.so    \$SDK/lib/libzmq.so
        echo \"SDK ready: \$SDK\"
        ls \$SDK/lib
    "

    echo -e "${BLUE}━━ 4/5 drop ~/.cpw-buildhost marker + remote .env.local${NC}"
    run_ssh "
        touch ~/.cpw-buildhost
        mkdir -p '$BUILD_REMOTE_DIR'
        cat > '$BUILD_REMOTE_DIR/.env.local' <<EOF
# Auto-written by 'just remote setup'. Marks this checkout as the build host.
BUILD_MODE=local
CPWORKER_LIBRARY_ROOT=$CPWORKER_LIBRARY_ROOT
CLOUD_PROBE_VERSION=$CLOUD_PROBE_VERSION
GOPROXY=$GOPROXY
EOF
        chmod 600 '$BUILD_REMOTE_DIR/.env.local'
        echo 'wrote marker + .env.local'
    "

    echo -e "${BLUE}━━ 5/5 sync project + verify build${NC}"
    run_rsync
    run_ssh "cd '$BUILD_REMOTE_DIR/build' && \
        export CPWORKER_LIBRARY_ROOT='$CPWORKER_LIBRARY_ROOT' CLOUD_PROBE_VERSION='$CLOUD_PROBE_VERSION' && \
        go run mage.go cpworker:linux 2>&1 | tail -5"

    echo
    echo -e "${GREEN}✓ Remote build host ready.${NC}"
    echo "  Try:   just dev build      (rsync + ssh-build)"
    echo "  Or:    just remote ssh     (then 'just dev build' runs locally on remote)"
}

cmd_install_just() {
    echo -e "${BLUE}Installing just(1) into ~/bin on remote...${NC}"
    run_ssh '
        mkdir -p ~/bin
        if [ -x ~/bin/just ]; then echo "already installed: $(~/bin/just --version)"; exit 0; fi
        curl -sSf https://just.systems/install.sh | bash -s -- --to ~/bin
        echo "installed: $(~/bin/just --version)"
        echo "(make sure ~/bin is on PATH — looks like it already is on this host)"
    '
}

case "${1:-help}" in
    ping)         cmd_ping ;;
    ssh)          cmd_ssh ;;
    info)         cmd_info ;;
    setup)        cmd_setup ;;
    install-just) cmd_install_just ;;
    help|--help|-h|"") show_help ;;
    *) echo -e "${RED}Unknown: remote $1${NC}"; show_help; exit 1 ;;
esac
