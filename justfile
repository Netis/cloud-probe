# cloud-probe justfile
# Router pattern: recipes dispatch to scripts/routers/*.sh
# Run `just` for the menu, `just <router>` for per-router detail.

set shell := ["bash", "-cu"]
set dotenv-load := true

project := "cloud-probe"
version := `git describe --tags --always --dirty 2>/dev/null || echo "0.9.x-dev"`

# Default: show help
default:
    @just help

# Show top-level menu
help:
    @echo ""
    @echo "📡 {{project}} {{version}} — packet capture & forwarding"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo ""
    @echo "🚀 Dev (build/test on whichever BUILD_MODE — use this most)"
    @echo "   just dev build [target]    Build  (default: all; cpworker|cpctl|cpdaemon|dockerpid|all)"
    @echo "   just dev test  [suite]     Test   (default: all; c|go|all)"
    @echo "   just dev clean             Wipe build artifacts on the build host"
    @echo "   just dev sync              rsync src → remote (no-op for local/orb)"
    @echo "   just dev shell             Open shell in the build env"
    @echo ""
    @echo "🖥️  Remote build host"
    @echo "   just remote ping           Test SSH"
    @echo "   just remote setup          One-time: install Go/cmake/libs + SDK skeleton"
    @echo "   just remote ssh            Interactive SSH"
    @echo "   just remote info           Versions + paths on the remote"
    @echo "   just remote install-just   Install just(1) on the remote"
    @echo ""
    @echo "🌐 Env (.env.local)"
    @echo "   just env init              Copy .env.example → .env.local"
    @echo "   just env show              Print effective build env"
    @echo ""
    @echo "⚡ Meta"
    @echo "   just version               {{project}} {{version}}"
    @echo "   just <router>              Detail help (e.g. 'just dev')"
    @echo ""

# Show version
version:
    @echo "{{project}} {{version}}"

# =============================================================================
# Routers — `just <name>` (no args) prints that router's detail help.
# =============================================================================

# Dev (build, test, clean, sync, shell — dispatches to BUILD_MODE backend)
dev *args:
    @bash scripts/routers/dev.sh {{args}}

# Remote (manage the SSH build host: ping, setup, ssh, info)
remote *args:
    @bash scripts/routers/remote.sh {{args}}

# Env (init/show .env.local)
env *args:
    @bash scripts/routers/env.sh {{args}}
