# cpworker Integration Tests

This directory contains end-to-end integration tests for cpworker, validating the complete flow from PCAP file input through various output modules.

## Overview

The integration test framework uses a data-driven approach where each test case consists of:
1. **Input PCAP file** (centralized in `testdata/pcaps/`) - Traffic to process
2. **cpworker configuration** (`config.json`) - How to process the traffic (references PCAP from `testdata/pcaps/`)
3. **Verification rules** (`verify.json`) - How to validate the output

## Directory Structure

```
cpworker/tests/integration/
├── go.mod                      # Go module definition
├── integration_test.go         # Main test runner (data-driven)
├── common_test.go              # Common test utilities
├── run_test.sh                 # Convenient test runner script
├── helpers/                    # Test helper packages
│   ├── runner.go               # cpworker process manager
│   ├── verifier.go             # Verification rule engine
│   ├── pcap_compare.go         # PCAP comparison utilities
│   ├── vxlan_capture.go        # VXLAN packet capturer
│   ├── gre_capture.go          # GRE packet capturer
│   └── zmq_capture.go          # ZMQ message capturer
├── testdata/
│   ├── pcaps/                  # Centralized PCAP files (shared)
│   │   ├── http.pcap           # HTTP traffic sample
│   │   └── ...                 # Other PCAP samples
│   ├── cases/                  # Test cases (user-provided)
│   │   ├── case1_file_basic/
│   │   │   ├── config.json     # cpworker config (references testdata/pcaps/http.pcap)
│   │   │   └── verify.json     # Verification rules
│   │   └── case2_vxlan_basic/
│   │       ├── config.json
│   │       └── verify.json
│   └── output/                 # Test outputs (auto-generated, gitignored)
│       ├── case1_file_basic/
│       │   ├── output.pcap
│       │   ├── cpworker_stdout.log
│       │   ├── cpworker_stderr.log
│       │   └── report.txt
│       └── case2_vxlan_basic/
│           ├── vxlan_capture.pcap
│           └── report.txt
```

## Running Tests

### Using the convenience script (recommended)

```bash
cd cpworker/tests/integration

# Run a specific test case
./run_test.sh case1_file_basic

# Run all test cases
./run_test.sh all

# List available test cases
./run_test.sh
```

### Using go test directly

```bash
cd cpworker/tests/integration

# Run a specific test case
sudo -E CPWORKER_BIN=/path/to/cpworker \
       LD_LIBRARY_PATH=/path/to/libs \
       /usr/local/go/bin/go test -v -run TestIntegration/case1_file_basic

# Run all tests
sudo -E CPWORKER_BIN=/path/to/cpworker \
       LD_LIBRARY_PATH=/path/to/libs \
       /usr/local/go/bin/go test -v -run TestIntegration
```

## Creating Test Cases

Each test case is a directory under `testdata/cases/` containing two required files:

### 1. config.json

cpworker configuration file. **Important**: The capturer must be type `pcap_file` and reference a PCAP file from `testdata/pcaps/`.

Example for file output:
```json
{
  "tasks": [{
    "capturer": {
      "type": "pcap_file",
      "pcap_file": {
        "file_name": "testdata/pcaps/http.pcap"
      }
    },
    "outputs": [{
      "type": "file",
      "file": {
        "file_name": "testdata/output/${case_name}/output.pcap"
      }
    }]
  }]
}
```

Example for VXLAN output:
```json
{
  "tasks": [{
    "capturer": {
      "type": "pcap_file",
      "pcap_file": {
        "file_name": "testdata/pcaps/http.pcap"
      }
    },
    "outputs": [{
      "type": "vxlan",
      "vxlan": {
        "host": "127.0.0.1",
        "port": 4789,
        "vni1": 100
      }
    }]
  }]
}
```

### 2. verify.json

Verification rules specifying how to validate the output.

#### Verification Rule Types

**packet_count_only** - Only verify packet count matches:
```json
{
  "rule": "packet_count_only"
}
```

**exact_match** - Verify packets match exactly (except timestamps):
```json
{
  "rule": "exact_match",
  "ignore_timestamp": true,
  "validate_layers": ["Ethernet", "IPv4", "TCP"]
}
```

**packet_count_range** - Verify packet count is within a range (for packet_split scenarios):
```json
{
  "rule": "packet_count_range",
  "min_packets": 10,
  "max_packets": 50
}
```

**no_verify** - Don't verify, just save output for manual inspection:
```json
{
  "rule": "no_verify"
}
```

## Supported Output Types

### File Output
cpworker writes directly to a PCAP file. Test framework reads and verifies it.

### VXLAN Output
Test framework captures VXLAN packets from the loopback interface, saving the complete encapsulated packets (Ethernet + IP + UDP + VXLAN + inner frame).

### GRE Output
Test framework captures GRE packets from the loopback interface, saving the complete encapsulated packets (Ethernet + IP + GRE + inner frame).

### ZMQ Output
Test framework:
- Receives ZMQ messages and saves them to `zmq_raw.dat`
- Extracts packets from ZMQ messages and saves to `zmq_packets.pcap`
- Generates statistics in `zmq_stats.json`

### Rotating File Output
Similar to file output, but test framework preserves all rotated file segments.

## Test Output

For each test case, the framework generates:

### Output Files (based on output type)
- **File**: `output.pcap`
- **VXLAN**: `vxlan_capture.pcap` (complete VXLAN packets)
- **GRE**: `gre_capture.pcap` (complete GRE packets)
- **ZMQ**: `zmq_raw.dat`, `zmq_packets.pcap`, `zmq_stats.json`

### Log Files
- `cpworker_stdout.log` - cpworker standard output
- `cpworker_stderr.log` - cpworker standard error

### Report
- `report.txt` - Verification results summary

Example report:
```
Test Case: case1_file_basic
Verify Rule: packet_count_only
Status: PASSED

Input Packets: 10
Output Packets: 10

Message: Packet count match: 10 packets

Timestamp: 2024-01-01T10:00:00Z
```

## Example: Creating a New Test Case

```bash
# Navigate to test cases directory
cd cpworker/tests/integration/testdata/cases

# Create test case directory
mkdir my_new_test

# Step 1: Add or reuse a PCAP file in testdata/pcaps/
# You can use existing ones like http.pcap or add a new one:
# tcpdump -i eth0 -w ../pcaps/my_traffic.pcap -c 20

# Step 2: Create config.json (reference PCAP from testdata/pcaps/)
cat > my_new_test/config.json <<'EOF'
{
  "tasks": [{
    "capturer": {
      "type": "pcap_file",
      "pcap_file": {
        "file_name": "testdata/pcaps/http.pcap"
      }
    },
    "outputs": [{
      "type": "vxlan",
      "vxlan": {
        "host": "127.0.0.1",
        "port": 4789,
        "vni1": 100
      }
    }]
  }]
}
EOF

# Step 3: Create verify.json
cat > my_new_test/verify.json <<'EOF'
{
  "rule": "packet_count_only"
}
EOF

# Run the test
cd ../..
./run_test.sh my_new_test
```

## Requirements

- Go 1.21 or later
- libpcap development headers (`libpcap-dev` on Debian/Ubuntu)
- ZeroMQ development headers (`libzmq3-dev` on Debian/Ubuntu)
- cpworker binary (built via `cd build && go run mage.go cpworker:linux`)
- Root/sudo privileges for network packet capture (VXLAN/GRE tests)

## Troubleshooting

### "CPWORKER_BIN environment variable not set"
Build cpworker first: `cd build && go run mage.go cpworker:linux`
The test:integration target sets this automatically.

### "Permission denied" when capturing packets
VXLAN and GRE tests require root privileges for packet capture:
```bash
sudo -E go test -v -run TestIntegration
```

### No test cases found
Ensure each test case directory has both required files:
- config.json
- verify.json

Input PCAP files should be in `testdata/pcaps/` and referenced in config.json.

### ZMQ test fails with "connection refused"
Check that the ZMQ endpoint in config.json is accessible and not already in use.

## Future Enhancements

- Performance benchmarking tests
- Stress testing with large PCAP files
- Multi-task configuration tests
- Error injection tests (corrupt PCAP, network failures)
- Docker-based isolated test environment
