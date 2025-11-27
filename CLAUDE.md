# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Netis Cloud Probe is a network packet capture and forwarding system. Captures packets on one device and forwards them (via GRE, VXLAN, ZMQ, or file) to another for analysis. Core packet capture engine in C (`cpworker`), management tools in Go (`cpdaemon`, `cpctl`, `dockerpid`).

## Build System

Uses **Mage** (Go-based build tool) as the primary build system. cpworker uses CMake internally.

### Build Commands

All commands run from the `build/` directory:

```bash
cd build

# Build all components for Linux
go run mage.go build:linux

# Build individual components
go run mage.go cpworker:linux
go run mage.go cpdaemon:linux
go run mage.go cpctl:linux
go run mage.go dockerpid:linux

# Other platforms: build:linuxARM64, build:darwin, build:darwinARM64, build:windows

# Clean
go run mage.go clean
```

### Required Environment Variables

- `CLOUD_PROBE_VERSION` - Required for final package creation
- `CPWORKER_LIBRARY_ROOT` - Root path for C library dependencies (libpcap, libzmq)
- `CPWORKER_CMAKE_TOOLCHAIN_FILE` - Optional, for cross-compilation
- `CPWORKER_CMAKE_BUILD_TYPE` - Optional, e.g. Release/Debug

### CMake Options (cpworker)

- `ENABLE_DPDK` (OFF) - Enable DPDK high-performance packet I/O
- `ENABLE_UNIT_TESTS` (ON) - Build with Unity test framework
- `ENABLE_LINK_STATIC_LIBPCAP` (OFF) - Static link libpcap
- `ENABLE_NO_PIE` (OFF) - For QEMU debugging

### Testing

**Unit tests** (C, Unity framework):
```bash
cd build && go run mage.go cpworker:linux
cd build/tmp/cpworker-linux-amd64 && make test
```

Unit test sources are in `cpworker/tests/unit/`. Each test file links all cpworker sources (except main.c). Add new tests by adding to the `unity_tests` list in `cpworker/tests/unit/CMakeLists.txt`.

**Integration tests** (Go):
```bash
cd cpworker/tests/integration
./build_cpworker.sh
./run_test.sh
```

Integration tests use Go's testing framework with helpers in `helpers/` for running cpworker, capturing output, and comparing pcap files. Test data in `testdata/`.

### Code Formatting

cpworker uses clang-format (`cpworker/.clang-format`): Allman braces, IndentWidth=4, ColumnLimit=120.

## Architecture

### Components

- **cpworker** (C) - Core packet capture engine. Entry: `cpworker/src/main.c`. Config-driven via JSON.
- **cpdaemon** (Go) - Management daemon that supervises cpworker processes, integrates with CPM (Cloud Probe Manager). Uses Cobra CLI, Viper config, Wire DI.
- **cpctl** (Go) - CLI control utility for cpworker/cpdaemon.
- **cpgolib** (Go) - Shared library: cpworker client, slogx logging utilities.
- **dockerpid** (Go, `cptools/dockerpid/`) - Docker container PID utility.

### cpworker Architecture

Modular pipeline design: **Capturer** -> **Task** -> **Output(s)**

- **Capturer**: Packet source abstraction (libpcap, pcap_file, dpdk_pdump). Network namespace support via `netns_linux.c`.
- **Task** (`task.c`, ~1600 lines): Central orchestration. Each task has one capturer and multiple outputs. Handles rate limiting, statistics, and the config reload lifecycle.
- **Output modules**: `output_gre.c`, `output_vxlan.c`, `output_zmq.c`, `output_file.c`, `output_rotating_file.c`, `output_null.c`. All implement a common init/write/close interface.
- **Request Pattern** (`req_pattern.c`): Detects traffic direction (request vs response) via auto-detection or custom BPF.
- **Control Plane** (`unix-manager.c`): Unix socket for runtime commands from cpdaemon/cpctl.
- **Config** (`config.c`, `cjson_utils.c`): JSON parsing. Examples in `cpworker/examples/`, `template.json` shows all fields.

### Config Reload System

cpworker supports live config reload without restarting:

- **Trigger**: SIGHUP signal or `reload_config` command via unix socket
- **Mechanism**: Dedicated reload thread communicates with main thread via mailbox protocol (message types: START, REUSED, REUSED_ACK, EXCHANGE, DESTROY, DONE)
- **Task identity**: Tasks use `fingerprint` field to match across reloads, allowing reuse of unchanged tasks
- **Ring buffer** (`ring_buffer.c`): SPSC queue with mempool for pipeline execution model

### Signal Handling

- `SIGHUP` - Triggers config reload (`task_manager_reload_signal()`)
- `SIGINT`/`SIGTERM` - Graceful shutdown
- `SIGPIPE` - Ignored

### Configuration Schema

Top-level fields: `log_level`, `cpu_affinity`, `control` (unix socket), `execution_model` (e.g. "rtc"), `pipeline` (`buffer_size_mb`)

Task-level: `fingerprint`, `req_pattern`, `capturer`, `outputs[]`

## Development Workflow

1. **Modifying cpworker (C code)**:
   - Edit sources in `cpworker/src/`
   - Build-verify cycle: `cd build && go run mage.go clean && go run mage.go cpworker:linux`
   - Test: `cd build/tmp/cpworker-linux-amd64 && make test`

2. **Modifying Go components**:
   - Edit sources in respective directories
   - Rebuild: `cd build && go run mage.go <component>:linux`
   - Go modules use local `replace` directives for cpgolib

3. **Adding new output type**:
   - Create `cpworker/src/output_<name>.c` and `.h`
   - Implement output interface (init, write, close)
   - Register in `config.c` output type parsing
   - CMakeLists.txt auto-discovers sources via glob

## Branch Strategy

- Main development branch: `0.9.x`
- PRs should target `0.9.x` unless specified otherwise

## Platform Support

- Primary: Linux (CentOS 7.9, Ubuntu 22.04)
- Also: macOS (Intel/ARM64), Windows
- Toolchain compatibility: GCC 4.8.5, glibc 2.17
