#!/usr/bin/env bash
# provision-repro.sh — set up an Ubuntu host (VM or OrbStack machine) to build
# cloud-probe and reproduce capture bugs. Idempotent; run as a sudo-capable user.
set -euo pipefail

echo ">> apt deps"
sudo apt-get update
sudo apt-get install -y \
  cmake build-essential pkg-config git \
  libpcap-dev libzmq3-dev \
  tcpreplay tcpdump

echo ">> Go toolchain (1.24.x)"
if ! command -v go >/dev/null || ! go version | grep -q 'go1.24'; then
  GO_TGZ="go1.24.1.linux-$(dpkg --print-architecture).tar.gz"
  curl -fsSL "https://go.dev/dl/${GO_TGZ}" -o "/tmp/${GO_TGZ}"
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "/tmp/${GO_TGZ}"
  grep -q '/usr/local/go/bin' ~/.profile || echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
  export PATH=$PATH:/usr/local/go/bin
fi

echo ">> Python (scapy) for crafted-traffic repro"
sudo apt-get install -y python3-pip
python3 -m pip install --user --upgrade scapy

echo ">> Done. go=$(go version 2>/dev/null). For C builds set CPWORKER_LIBRARY_ROOT (see .env.example)."
