#!/usr/bin/env bash
# ==============================================================================
# Env — manage .env.local
# ==============================================================================
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/common.sh"

show_help() {
    cat <<EOF

  🌐 Env — .env.local management

  just env init     Copy .env.example → .env.local (won't clobber existing)
  just env show     Print effective build env

EOF
}

cmd_init() {
    local src="$PROJECT_ROOT/.env.example" dst="$PROJECT_ROOT/.env.local"
    [[ ! -f "$src" ]] && { echo -e "${RED}.env.example missing${NC}"; exit 1; }
    if [[ -f "$dst" ]]; then
        echo -e "${YELLOW}.env.local already exists — leaving untouched${NC}"
        echo "  diff vs .env.example:"
        diff -u "$src" "$dst" | head -40 || true
        exit 0
    fi
    cp "$src" "$dst"
    chmod 600 "$dst"
    echo -e "${GREEN}✓ created .env.local — edit it and re-run 'just env show'${NC}"
}

cmd_show() {
    cat <<EOF

  Effective build env (after .env.local + defaults):
    BUILD_MODE                = ${BUILD_MODE}
    BUILD_SSH_HOST            = ${BUILD_SSH_HOST}
    BUILD_SSH_KEY             = ${BUILD_SSH_KEY:-(default ssh keys)}
    BUILD_REMOTE_DIR          = ${BUILD_REMOTE_DIR}
    BUILD_SSH_ROOT_PASSWORD   = $([[ -n "$BUILD_SSH_ROOT_PASSWORD" ]] && echo '***' || echo '(not set)')
    BUILD_ORB_MACHINE         = ${BUILD_ORB_MACHINE}
    CPWORKER_LIBRARY_ROOT     = ${CPWORKER_LIBRARY_ROOT}
    CLOUD_PROBE_VERSION       = ${CLOUD_PROBE_VERSION}
    GOPROXY                   = ${GOPROXY}

  .env.local: $([[ -f "$PROJECT_ROOT/.env.local" ]] && echo "$PROJECT_ROOT/.env.local" || echo '(not present — run "just env init")')
  Buildhost marker (~/.cpw-buildhost): $([[ -f "$HOME/.cpw-buildhost" ]] && echo present || echo absent)

EOF
}

case "${1:-help}" in
    init) cmd_init ;;
    show) cmd_show ;;
    help|--help|-h|"") show_help ;;
    *) echo -e "${RED}Unknown: env $1${NC}"; show_help; exit 1 ;;
esac
