#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

echo "==> Cleaning build directory..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

echo "==> Running cmake..."
cd "${BUILD_DIR}"
cmake -DLIBRARY_ROOT="${CLOUD_PROBE_CXX_LIBS_PATH}" -DCMAKE_EXPORT_COMPILE_COMMANDS=1 ..

echo "==> Building..."
make -j"$(nproc)"

echo "==> Setting capabilities..."
sudo setcap cap_net_raw,cap_net_admin=eip "./cpworker"
getcap "./cpworker"

echo "==> Done."
