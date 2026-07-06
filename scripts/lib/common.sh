#!/usr/bin/env bash
# ==============================================================================
# Shared helpers for scripts/routers/*.sh
# ==============================================================================
# - Loads .env.local (with sane defaults so routers work even unconfigured)
# - Auto-detects BUILD_MODE if unset
# - Provides ssh/rsync helpers + run_on_buildhost() dispatcher

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# Resolve PROJECT_ROOT from the *router* script that sourced this file.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Load .env.local if present (set -a exports every var assigned).
# Tests set CPW_SKIP_ENV_LOCAL=1 to avoid the user's personal env leaking in.
if [[ -z "${CPW_SKIP_ENV_LOCAL:-}" && -f "$PROJECT_ROOT/.env.local" ]]; then
    set -a; source "$PROJECT_ROOT/.env.local"; set +a
fi

# All values come from .env.local (or the user's shell). Only safe, non-personal
# defaults live here — anything host/user/locale specific must be set explicitly.
BUILD_MODE="${BUILD_MODE:-}"
BUILD_SSH_HOST="${BUILD_SSH_HOST:-}"
BUILD_SSH_KEY="${BUILD_SSH_KEY:-}"
BUILD_REMOTE_DIR="${BUILD_REMOTE_DIR:-}"
BUILD_SSH_ROOT_PASSWORD="${BUILD_SSH_ROOT_PASSWORD:-}"
BUILD_ORB_MACHINE="${BUILD_ORB_MACHINE:-}"
CPWORKER_LIBRARY_ROOT="${CPWORKER_LIBRARY_ROOT:-}"
CLOUD_PROBE_VERSION="${CLOUD_PROBE_VERSION:-0.9.x-dev}"
GOPROXY="${GOPROXY:-}"

# Local developer checkouts commonly keep the C dependencies in a sibling repo:
#   ../cloud-probe-thirdparty/libs/<os>-<arch>
# Auto-detect that path so `just dev build/test` works without a personal
# .env.local on Linux build machines.
if [[ -z "$CPWORKER_LIBRARY_ROOT" ]]; then
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)  _cpw_lib_platform="linux-amd64" ;;
        Linux-aarch64|Linux-arm64) _cpw_lib_platform="linux-arm64" ;;
        Darwin-x86_64) _cpw_lib_platform="darwin-amd64" ;;
        Darwin-arm64)  _cpw_lib_platform="darwin-arm64" ;;
        *)             _cpw_lib_platform="" ;;
    esac
    _cpw_lib_root="$PROJECT_ROOT/../cloud-probe-thirdparty/libs/$_cpw_lib_platform"
    if [[ -n "$_cpw_lib_platform" && -d "$_cpw_lib_root" ]]; then
        CPWORKER_LIBRARY_ROOT="$_cpw_lib_root"
    fi
    unset _cpw_lib_platform _cpw_lib_root
fi

# ---------------------------------------------------------------------------
# BUILD_MODE auto-detection
# ---------------------------------------------------------------------------
# Order:
#   1. explicit BUILD_MODE in env wins
#   2. ~/.cpw-buildhost marker (dropped by `just remote setup`)
#   3. on Linux AND $PWD == $BUILD_REMOTE_DIR → local
#   4. local dependency SDK present → local
#   5. ssh config present → ssh
#   6. fallback → local (so unconfigured checkouts can still run Go tests/helpful errors)
detect_build_mode() {
    if [[ -n "$BUILD_MODE" ]]; then echo "$BUILD_MODE"; return; fi
    if [[ -f "$HOME/.cpw-buildhost" ]]; then echo "local"; return; fi
    if [[ -n "$BUILD_REMOTE_DIR" && "$(uname -s)" == "Linux" && "$PWD" == "$BUILD_REMOTE_DIR" ]]; then
        echo "local"; return
    fi
    if [[ -n "$CPWORKER_LIBRARY_ROOT" && -d "$CPWORKER_LIBRARY_ROOT" ]]; then
        echo "local"; return
    fi
    if [[ -n "$BUILD_SSH_HOST" && -n "$BUILD_REMOTE_DIR" ]]; then
        echo "ssh"; return
    fi
    echo "local"
}
BUILD_MODE="$(detect_build_mode)"

# ---------------------------------------------------------------------------
# SSH / rsync helpers
# ---------------------------------------------------------------------------
_ssh_args=(-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
[[ -n "$BUILD_SSH_KEY" ]] && _ssh_args+=(-o IdentitiesOnly=yes -i "$BUILD_SSH_KEY")

run_ssh()      { ssh "${_ssh_args[@]}" "$BUILD_SSH_HOST" "$@"; }
run_ssh_tty()  { ssh "${_ssh_args[@]}" -t "$BUILD_SSH_HOST" "$@"; }

# Run a script as root on the remote. Reads the script from stdin.
# We can't `sudo` (ts is not in sudoers), so we pipe through `su -`.
#
# Security: the password travels over ssh's stdin, never on a command line.
# The old version interpolated $BUILD_SSH_ROOT_PASSWORD directly into the
# remote command string, which exposed it via `ps` on both ends (and broke
# when the password contained a single quote). The remote driver reads the
# password from stdin and pipes it straight into `su`, so neither local nor
# remote `ps` ever sees it. The script payload is base64'd into argv — not
# secret, just an encoding convenience.
run_ssh_root() {
    if [[ -z "$BUILD_SSH_ROOT_PASSWORD" ]]; then
        echo -e "${RED}BUILD_SSH_ROOT_PASSWORD not set in .env.local${NC}" >&2
        return 1
    fi
    local script b64
    script="$(cat)"
    b64="$(printf '%s' "$script" | base64 | tr -d '\n')"

    printf '%s\n' "$BUILD_SSH_ROOT_PASSWORD" | run_ssh \
        "IFS= read -r __cpw_pw && printf '%s\n' \"\$__cpw_pw\" | su - root -c \"echo '$b64' | base64 -d | bash\""
}

run_rsync() {
    local rsh="ssh ${_ssh_args[*]}"
    rsync -az --stats -e "$rsh" \
        --exclude='.git/' --exclude='.env.local' \
        --exclude='build/dist/' --exclude='build/tmp/' \
        --exclude='cpworker/build/' \
        --exclude='*.o' --exclude='*.a' \
        --exclude='.DS_Store' --exclude='.worktrees/' \
        "$PROJECT_ROOT/" "$BUILD_SSH_HOST:$BUILD_REMOTE_DIR/" 2>&1 | tail -5
}

# ---------------------------------------------------------------------------
# run_on_buildhost — dispatch a build/test command to the configured backend
# ---------------------------------------------------------------------------
# Args:
#   $1: shell command to run inside PROJECT_ROOT on the build host
# Forwards CPWORKER_LIBRARY_ROOT / CLOUD_PROBE_VERSION / GOPROXY env.
#
# - local: run directly here
# - ssh:   rsync, then ssh + cd + run
# - orb:   `orb -m $machine bash -c "cd $PWD && cmd"` (no rsync, shared FS)
run_on_buildhost() {
    local cmd="$1"
    local exports="export CPWORKER_LIBRARY_ROOT='$CPWORKER_LIBRARY_ROOT' CLOUD_PROBE_VERSION='$CLOUD_PROBE_VERSION' GOPROXY='$GOPROXY'"

    case "$BUILD_MODE" in
        local)
            echo -e "${BLUE}▶ build mode: local${NC}"
            bash -c "$exports; $cmd"
            ;;
        ssh)
            require_var BUILD_SSH_HOST BUILD_REMOTE_DIR
            echo -e "${BLUE}▶ build mode: ssh ($BUILD_SSH_HOST:$BUILD_REMOTE_DIR)${NC}"
            run_rsync
            run_ssh "cd '$BUILD_REMOTE_DIR' && $exports && $cmd"
            ;;
        orb)
            require_var BUILD_ORB_MACHINE
            command -v orb >/dev/null || { echo -e "${RED}orb CLI not installed${NC}"; exit 1; }
            echo -e "${BLUE}▶ build mode: orb (machine: $BUILD_ORB_MACHINE)${NC}"
            orb -m "$BUILD_ORB_MACHINE" bash -c "cd '$PROJECT_ROOT' && $exports && $cmd"
            ;;
        "")
            echo -e "${RED}BUILD_MODE not set.${NC} Run ${CYAN}just env init${NC} and edit .env.local." >&2
            exit 1
            ;;
        *)
            echo -e "${RED}Unknown BUILD_MODE: $BUILD_MODE${NC}" >&2
            exit 1
            ;;
    esac
}

# Fail fast if required env vars are empty.
require_var() {
    local missing=()
    for v in "$@"; do
        [[ -z "${!v:-}" ]] && missing+=("$v")
    done
    if (( ${#missing[@]} )); then
        echo -e "${RED}Missing required env: ${missing[*]}${NC}" >&2
        echo "  Set these in .env.local (run ${CYAN}just env init${NC} for a template)." >&2
        exit 1
    fi
}

# Convenience: shell into the build env (interactive)
shell_on_buildhost() {
    case "$BUILD_MODE" in
        local) exec bash ;;
        ssh)   run_ssh_tty "cd '$BUILD_REMOTE_DIR' && exec bash -l" ;;
        orb)
            command -v orb >/dev/null || { echo -e "${RED}orb CLI not installed${NC}"; exit 1; }
            exec orb -m "$BUILD_ORB_MACHINE" -d "$PROJECT_ROOT" bash -l
            ;;
    esac
}
