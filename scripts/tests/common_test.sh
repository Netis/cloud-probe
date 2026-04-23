#!/usr/bin/env bash
# Tests for scripts/lib/common.sh — focused on the credential-handling fix.
#
# Strategy: shim `ssh` via PATH with a fake that records its argv and stdin
# to files we can inspect. Source common.sh as a router would, call
# run_ssh_root with a known password, and assert:
#   - the password never appears in ssh's argv (i.e. not visible in `ps`)
#   - the password DOES appear on ssh's stdin (how the remote driver reads it)
# This locks in the fix for the "password leaks via ps" finding.
#
# CPW_SKIP_ENV_LOCAL=1 keeps the user's personal .env.local from overriding
# our test fixtures when common.sh is sourced.

set -u

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

shim_dir="$(mktemp -d)"
trap 'rm -rf "$shim_dir"' EXIT

cat >"$shim_dir/ssh" <<'SHIM'
#!/usr/bin/env bash
# Fake ssh: persist argv + stdin for the test to inspect, then exit 0.
: >"${SSH_ARGV_FILE:?SSH_ARGV_FILE required}"
for a in "$@"; do printf '%s\n' "$a" >>"$SSH_ARGV_FILE"; done
cat >"${SSH_STDIN_FILE:?SSH_STDIN_FILE required}"
SHIM
chmod +x "$shim_dir/ssh"
export PATH="$shim_dir:$PATH"
export CPW_SKIP_ENV_LOCAL=1

pass=0
fail=0
report_ok()   { pass=$((pass + 1)); echo "  ok   $1"; }
report_fail() { fail=$((fail + 1)); echo "  FAIL $1${2:+ — $2}"; }
assert_ok()   { eval "$1" && report_ok "$2" || report_fail "$2" "${3:-}"; }

run_test_password_goes_via_stdin() {
    echo "# test: password via ssh stdin, never in argv"
    SSH_ARGV_FILE="$(mktemp)"
    SSH_STDIN_FILE="$(mktemp)"
    export SSH_ARGV_FILE SSH_STDIN_FILE

    (
        export BUILD_SSH_HOST="build@example.com"
        export BUILD_SSH_ROOT_PASSWORD="super-secret-pw-42"
        export BUILD_MODE="ssh"
        unset BUILD_SSH_KEY
        source "$THIS_DIR/../lib/common.sh"
        printf 'echo hi\n' | run_ssh_root >/dev/null 2>&1
    )

    local argv stdin_payload
    argv="$(cat "$SSH_ARGV_FILE")"
    stdin_payload="$(cat "$SSH_STDIN_FILE")"

    # Precheck: if argv capture is empty the "absent" assertion below would
    # pass vacuously. Fail loudly instead.
    assert_ok "[[ -n \"\$argv\" ]]" "ssh shim captured argv" "argv file empty"
    assert_ok "! grep -Fq 'super-secret-pw-42' <<<\"\$argv\"" \
        "password absent from ssh argv" "argv=$argv"
    assert_ok "grep -Fq 'super-secret-pw-42' <<<\"\$stdin_payload\"" \
        "password present in ssh stdin" "stdin=$stdin_payload"
    assert_ok "grep -Fq 'build@example.com' <<<\"\$argv\"" \
        "ssh host still in argv" "argv=$argv"

    rm -f "$SSH_ARGV_FILE" "$SSH_STDIN_FILE"
}

run_test_requires_password() {
    echo "# test: run_ssh_root fails fast when BUILD_SSH_ROOT_PASSWORD unset"
    local rc
    (
        export BUILD_SSH_HOST="build@example.com"
        export BUILD_MODE="ssh"
        unset BUILD_SSH_ROOT_PASSWORD
        source "$THIS_DIR/../lib/common.sh"
        # Re-unset after source in case a stray default reinstates it.
        unset BUILD_SSH_ROOT_PASSWORD
        printf 'noop\n' | run_ssh_root >/dev/null 2>&1
    ) && rc=0 || rc=$?

    assert_ok "[[ $rc -ne 0 ]]" "run_ssh_root exits nonzero without password"
}

run_test_password_with_special_chars() {
    echo "# test: password containing shell metacharacters is handled safely"
    SSH_ARGV_FILE="$(mktemp)"
    SSH_STDIN_FILE="$(mktemp)"
    export SSH_ARGV_FILE SSH_STDIN_FILE

    # Old implementation broke on passwords containing single quotes because
    # it interpolated the literal password inside single-quoted shell strings.
    local tricky='pw with "quotes" $and spaces'
    (
        export BUILD_SSH_HOST="build@example.com"
        export BUILD_SSH_ROOT_PASSWORD="$tricky"
        export BUILD_MODE="ssh"
        unset BUILD_SSH_KEY
        source "$THIS_DIR/../lib/common.sh"
        printf 'echo hi\n' | run_ssh_root >/dev/null 2>&1
    )

    local stdin_payload
    stdin_payload="$(cat "$SSH_STDIN_FILE")"
    assert_ok "grep -Fq '$tricky' <<<\"\$stdin_payload\"" \
        "tricky password passes through stdin intact" "stdin=$stdin_payload"

    rm -f "$SSH_ARGV_FILE" "$SSH_STDIN_FILE"
}

run_test_password_goes_via_stdin
run_test_requires_password
run_test_password_with_special_chars

echo
if (( fail > 0 )); then
    echo "FAILED: $fail/$((pass + fail))"
    exit 1
fi
echo "PASSED: $pass/$pass"
