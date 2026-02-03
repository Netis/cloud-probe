# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Netis Cloud Probe (formerly Packet Agent) is a network packet capture and forwarding system designed to capture packets on one device and forward them to another for analysis. The project consists of multiple components written in C and Go, with the core packet capture engine in C and management tools in Go.

## Build System

The project uses **Mage** (a Make/rake-like build tool using Go) as the primary build system. The cpworker component uses CMake.

### Build Commands

Build all components for Linux:
```bash
cd build
go run mage.go build:linux
```

Build individual components:
```bash
go run mage.go cpworker:linux      # C-based packet capture worker
go run mage.go cpdaemon:linux      # Go-based daemon
go run mage.go cpctl:linux         # Go-based control utility
go run mage.go dockerpid:linux     # Go-based Docker PID tool
```

Build for other platforms:
```bash
go run mage.go build:linuxARM64
go run mage.go build:darwin
go run mage.go build:darwinARM64
go run mage.go build:windows
```

Clean build artifacts:
```bash
go run mage.go clean
```

Output location: `./build/dist/cloud-probe-<version>-<os>-<arch>.tar.gz`

### Testing

Run cpworker tests (uses Unity test framework):
```bash
cd cpworker/build
cmake ../
make test
```

## Architecture

### Components

1. **cpworker** (C, ~66 source files)
   - Core packet capture engine built on libpcap
   - Located in `cpworker/src/`
   - Dependencies: libpcap, libzmq, pthread
   - Main entry: `cpworker/src/main.c`
   - Configuration-driven via JSON files

2. **cpdaemon** (Go)
   - Management daemon for cpworker processes
   - Located in `cpdaemon/`
   - Integrates with CPM (Cloud Probe Manager)
   - Packages: cgroup, cpm, httpmix, tool, worker, version

3. **cpctl** (Go)
   - Command-line control utility
   - Located in `cpctl/`
   - Used to interact with cpworker or cpdaemon

4. **dockerpid** (Go)
   - Utility for getting Docker container PIDs
   - Located in `cptools/dockerpid/`

5. **cpgolib** (Go)
   - Shared Go libraries
   - Contains cpworker client library and logging utilities (slogx)

### cpworker Architecture

The cpworker component follows a modular design:

- **Capturer Layer**: `libpcap.c`, `capturer.h` - Packet capture interface
  - Supports libpcap for packet capture
  - Optional DPDK support (compile-time flag)
  - Network namespace support via `netns_linux.c`

- **Request Pattern**: `req_pattern.c` - Traffic direction detection
  - Auto-detection or custom BPF patterns
  - Determines if packets are requests or responses

- **Output Modules**: Multiple output formats
  - `output_gre.c` - GRE encapsulation
  - `output_vxlan.c` - VXLAN encapsulation
  - `output_zmq.c` - ZeroMQ streaming
  - `output_file.c` - PCAP file output
  - `output_rotating_file.c` - Rotating PCAP files
  - `output_null.c` - Null output (testing)

- **Task Management**: `task.c` - Manages capture tasks
  - Each task has one capturer and multiple outputs
  - Rate limiting via `ratelimit.c`
  - Statistics tracking via `stats.c`

- **Control Plane**: `unix-manager.c` - Unix socket interface
  - Receives commands from cpdaemon/cpctl
  - Runtime configuration updates

- **Utilities**:
  - `bpf_util.c` - BPF filter helpers
  - `if_util.c` - Network interface utilities
  - `affinity_linux.c` - CPU affinity management
  - Protocol headers: `ip.h`, `tcp.h`, `udp.h`, `gre.h`, `vxlan.h`, `vlan.h`, `mpls.h`

### Configuration System

cpworker uses JSON configuration files (`config.c`, `cjson_utils.c`):
- Top-level: log level, CPU affinity, control socket path
- Tasks array: Each task defines capturer + outputs
- Examples located in `cpworker/examples/`

## Running cpworker

Basic usage:
```bash
cpworker -c <config-file.json>
```

Example configurations in `cpworker/examples/`:
- libpcap with GRE output
- libpcap with VXLAN output
- libpcap with ZMQ output
- File output with rotation

### Key Configuration Concepts

1. **Capturer**: Defines packet source (interface, BPF filter, snaplen, buffer size)
2. **Outputs**: One or more destinations (GRE/VXLAN/ZMQ/file)
3. **Request Pattern**: Traffic direction detection (auto or custom)
4. **Rate Limiting**: Per-output bandwidth limits
5. **CPU Affinity**: Pin to specific CPUs for performance

## Dependencies

### C/C++ Libraries (cpworker)
- libpcap 1.6.2+ (packet capture)
- libzmq 4.3.3+ (ZeroMQ messaging)
- pthread (threading)
- Optional: DPDK (high-performance packet I/O)

Install to `$CLOUD_PROBE_CXX_LIBS_SDK/linux-amd64/` before building.

### Go Modules
- Uses Go modules (go.mod in cpdaemon/, cpctl/, cptools/dockerpid/)
- Magefile dependency for build system
- See individual go.mod files for specific dependencies

## Development Workflow

1. **Modifying cpworker (C code)**:
   - Edit sources in `cpworker/src/`
   - **Build Verification** (Required after every change):
     1. Clean: `cd build && go run mage.go clean`
     2. Rebuild: `cd build && go run mage.go cpworker:linux`
     3. Test: `cd build/tmp/cpworker-linux-amd64 && make test`

2. **Modifying Go components**:
   - Edit sources in respective directories (cpdaemon/, cpctl/, etc.)
   - Rebuild: `cd build && go run mage.go <component>:linux`

3. **Adding new output type**:
   - Create `cpworker/src/output_<name>.c` and `.h`
   - Implement output interface (init, write, close)
   - Register in `config.c` output type parsing
   - Update CMakeLists.txt if needed (auto-detected via glob)

4. **Updating configuration schema**:
   - Modify parsing in `cpworker/src/config.c`
   - Update documentation in `docs/USAGE-CPWORKER.md`
   - Add example in `cpworker/examples/`

## Branch Strategy

- Main development branch: `0.9.x`
- Feature branches: Use descriptive names
- PRs should target `0.9.x` unless specified otherwise

## Platform Support

- Primary: Linux (CentOS 7.9, Ubuntu 22.04)
- Also supports: macOS (Intel/ARM64), Windows
- Cross-compilation supported via Mage build targets
