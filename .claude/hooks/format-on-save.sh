#!/usr/bin/env bash
# Claude Code PostToolUse hook: auto-format source files after Edit/Write
# Mirrors .vscode/settings.json formatting configuration
# Input: JSON on stdin with tool_name and tool_input.file_path

set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

if [ -z "$FILE_PATH" ] || [ ! -f "$FILE_PATH" ]; then
    exit 0
fi

case "$FILE_PATH" in
    */cpworker/*.c | */cpworker/*.h)
        clang-format -i "$FILE_PATH"
        ;;
    */cpdaemon/*.go | */cpctl/*.go | */cpgolib/*.go | */cptools/*.go)
        goimports -local github.com/Netis -w "$FILE_PATH"
        gofumpt -w "$FILE_PATH"
        ;;
esac
