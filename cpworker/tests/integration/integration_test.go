package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netis-cloud-probe/cloud-probe/cpworker/tests/integration/helpers"
)

// TestCase represents a single integration test case
type TestCase struct {
	Name             string
	Dir              string
	InputPCAP        string
	ConfigPath       string
	VerifyConfigPath string
	Config           *CpworkerConfig
}

// CpworkerConfig represents the cpworker configuration
type CpworkerConfig struct {
	Tasks []Task `json:"tasks"`
}

// Task represents a cpworker task configuration
type Task struct {
	Capturer Capturer `json:"capturer"`
	Outputs  []Output `json:"outputs"`
}

// Capturer represents the capturer configuration
type Capturer struct {
	Type     string                 `json:"type"`
	PcapFile map[string]interface{} `json:"pcap_file,omitempty"`
}

// Output represents an output configuration
type Output struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:",inline"`
}

// UnmarshalJSON custom unmarshaler for Output to handle inline configs
func (o *Output) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if typeVal, ok := raw["type"].(string); ok {
		o.Type = typeVal
		o.Config = raw
	}

	return nil
}

// TestIntegration is the main integration test entry point
func TestIntegration(t *testing.T) {
	// Check if cpworker binary is set
	if os.Getenv("CPWORKER_BIN") == "" {
		t.Fatal("CPWORKER_BIN environment variable not set")
	}

	// Discover test cases
	cases, err := discoverTestCases(getCasesDir())
	if err != nil {
		t.Fatalf("Failed to discover test cases: %v", err)
	}

	if len(cases) == 0 {
		t.Skip("No test cases found in " + getCasesDir())
	}

	// Run each test case
	for _, tc := range cases {
		tc := tc // Capture range variable
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			runTestCase(t, tc)
		})
	}
}

// discoverTestCases scans the test cases directory and returns all valid test cases
func discoverTestCases(casesDir string) ([]*TestCase, error) {
	var cases []*TestCase

	entries, err := os.ReadDir(casesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return cases, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		caseDir := filepath.Join(casesDir, entry.Name())

		// Check for required files
		configPath := filepath.Join(caseDir, "config.json")
		verifyPath := filepath.Join(caseDir, "verify.json")

		if _, err := os.Stat(configPath); err != nil {
			continue // Skip if no config.json
		}
		if _, err := os.Stat(verifyPath); err != nil {
			continue // Skip if no verify.json
		}

		// Load config
		config, err := loadCpworkerConfig(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load config for %s: %w", entry.Name(), err)
		}

		// Extract input PCAP path from config
		var inputPCAP string
		if len(config.Tasks) > 0 && config.Tasks[0].Capturer.Type == "pcap_file" {
			if pcapFile, ok := config.Tasks[0].Capturer.PcapFile["file_name"].(string); ok {
				// Convert relative path to absolute path from integration test directory
				if !filepath.IsAbs(pcapFile) {
					inputPCAP = filepath.Join(getTestDataDir(), "..", pcapFile)
				} else {
					inputPCAP = pcapFile
				}
			}
		}

		if inputPCAP == "" {
			return nil, fmt.Errorf("no input pcap_file specified in config for %s", entry.Name())
		}

		// Verify input PCAP exists
		if _, err := os.Stat(inputPCAP); err != nil {
			return nil, fmt.Errorf("input PCAP not found for %s: %s", entry.Name(), inputPCAP)
		}

		cases = append(cases, &TestCase{
			Name:             entry.Name(),
			Dir:              caseDir,
			InputPCAP:        inputPCAP,
			ConfigPath:       configPath,
			VerifyConfigPath: verifyPath,
			Config:           config,
		})
	}

	return cases, nil
}

// loadCpworkerConfig loads cpworker configuration from JSON file
func loadCpworkerConfig(path string) (*CpworkerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config CpworkerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// runTestCase executes a single test case
func runTestCase(t *testing.T, tc *TestCase) {
	// Create output directory
	outputDir := setupTestOutputDir(t, tc.Name)

	// Determine output type from config
	if len(tc.Config.Tasks) == 0 || len(tc.Config.Tasks[0].Outputs) == 0 {
		t.Fatal("No outputs defined in config")
	}

	outputType := tc.Config.Tasks[0].Outputs[0].Type

	// Start appropriate capturer based on output type
	var capturer interface{ Stop() error }
	var outputPCAP string
	var err error

	switch outputType {
	case "file":
		outputPCAP = getFileOutputPath(tc.Config.Tasks[0].Outputs[0].Config)
		if dir := filepath.Dir(outputPCAP); dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("Failed to create output directory %s: %v", dir, err)
			}
		}

	case "vxlan":
		// VXLAN output - capture from network
		outputPCAP = filepath.Join(outputDir, "vxlan_capture.pcap")
		vxlanPort := getVXLANPort(tc.Config.Tasks[0].Outputs[0].Config)
		capturer, err = helpers.NewVXLANCapturer("lo", vxlanPort, outputPCAP)
		if err != nil {
			t.Fatalf("Failed to create VXLAN capturer: %v", err)
		}
		if err := capturer.(*helpers.VXLANCapturer).Start(); err != nil {
			t.Fatalf("Failed to start VXLAN capturer: %v", err)
		}
		defer capturer.Stop()

	case "gre":
		// GRE output - capture from network
		outputPCAP = filepath.Join(outputDir, "gre_capture.pcap")
		capturer, err = helpers.NewGRECapturer("lo", outputPCAP)
		if err != nil {
			t.Fatalf("Failed to create GRE capturer: %v", err)
		}
		if err := capturer.(*helpers.GRECapturer).Start(); err != nil {
			t.Fatalf("Failed to start GRE capturer: %v", err)
		}
		defer capturer.Stop()

	case "zmq":
		// ZMQ output - receive ZMQ messages
		outputPCAP = filepath.Join(outputDir, "zmq_packets.pcap")
		rawOutput := filepath.Join(outputDir, "zmq_raw.dat")
		statsOutput := filepath.Join(outputDir, "zmq_stats.json")
		receiverSrcDir := "helpers/zmq_receiver"

		endpoint := getZMQEndpoint(tc.Config.Tasks[0].Outputs[0].Config)
		t.Logf("Creating ZMQ capturer on endpoint: %s", endpoint)
		capturer, err = helpers.NewZMQCapturer(endpoint, rawOutput, outputPCAP, statsOutput, receiverSrcDir)
		if err != nil {
			t.Fatalf("Failed to create ZMQ capturer: %v", err)
		}
		t.Logf("ZMQ capturer created successfully")
		zmqCapturer := capturer.(*helpers.ZMQCapturer)
		if err := zmqCapturer.Start(); err != nil {
			t.Fatalf("Failed to start ZMQ capturer: %v", err)
		}
		defer zmqCapturer.Stop()

	default:
		t.Fatalf("Unsupported output type: %s", outputType)
	}

	t.Logf("Waiting 500ms for capturer to start...")
	time.Sleep(500 * time.Millisecond)

	// Get absolute path to config
	t.Logf("Getting absolute config path for: %s", tc.ConfigPath)
	absConfigPath, err := filepath.Abs(tc.ConfigPath)
	if err != nil {
		t.Fatalf("Failed to get absolute config path: %v", err)
	}
	t.Logf("Absolute config path: %s", absConfigPath)

	// Run cpworker
	t.Logf("Creating cpworker runner...")
	runner, err := helpers.NewCpworkerRunner(absConfigPath, 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to create cpworker runner: %v", err)
	}
	t.Logf("Cpworker runner created successfully")

	// Capture cpworker output
	t.Logf("Creating log files...")
	stdoutFile, err := os.Create(filepath.Join(outputDir, "cpworker_stdout.log"))
	if err != nil {
		t.Fatalf("Failed to create stdout log: %v", err)
	}
	stderrFile, err := os.Create(filepath.Join(outputDir, "cpworker_stderr.log"))
	if err != nil {
		t.Fatalf("Failed to create stderr log: %v", err)
	}
	defer stdoutFile.Close()
	defer stderrFile.Close()

	runner.SetStdout(stdoutFile)
	runner.SetStderr(stderrFile)

	t.Logf("Starting cpworker...")
	if err := runner.Start(); err != nil {
		t.Fatalf("Failed to start cpworker: %v", err)
	}
	t.Logf("Cpworker started successfully")

	// For pcap_file input, wait a bit for processing then force stop
	// cpworker doesn't auto-exit after reading pcap file
	time.Sleep(5 * time.Second)

	// Stop cpworker gracefully
	if err := runner.Stop(); err != nil {
		t.Logf("Failed to stop cpworker gracefully: %v", err)
	}

	// Stop capturer before verification so output files (e.g. zmq_stats.json) are flushed
	if capturer != nil {
		time.Sleep(1 * time.Second)
		capturer.Stop()
	}

	// Load verify config
	verifyConfig, err := helpers.LoadVerifyConfig(tc.VerifyConfigPath)
	if err != nil {
		t.Fatalf("Failed to load verify config: %v", err)
	}

	// Perform verification
	result, err := helpers.Verify(tc.InputPCAP, outputPCAP, verifyConfig)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	// Generate report
	report := generateReport(tc, result, verifyConfig)
	reportPath := filepath.Join(outputDir, "report.txt")
	if err := os.WriteFile(reportPath, []byte(report), 0o644); err != nil {
		t.Errorf("Failed to write report: %v", err)
	}

	// Check result
	if !result.Passed {
		t.Errorf("Test failed:\n%s", report)
	} else {
		t.Logf("Test passed: %s", result.Message)
	}
}

// generateReport generates a human-readable test report
func generateReport(tc *TestCase, result *helpers.VerifyResult, config *helpers.VerifyConfig) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Test Case: %s\n", tc.Name))
	var ruleNames []string
	for _, r := range config.Rules {
		ruleNames = append(ruleNames, string(r.Rule))
	}
	sb.WriteString(fmt.Sprintf("Verify Rules: %s\n", strings.Join(ruleNames, ", ")))
	sb.WriteString(fmt.Sprintf("Status: %s\n\n", map[bool]string{true: "PASSED", false: "FAILED"}[result.Passed]))

	sb.WriteString(fmt.Sprintf("Input Packets: %d\n", result.InputPackets))
	sb.WriteString(fmt.Sprintf("Output Packets: %d\n\n", result.OutputPackets))

	sb.WriteString(fmt.Sprintf("Message: %s\n", result.Message))

	if len(result.Differences) > 0 {
		sb.WriteString(fmt.Sprintf("\nDifferences Found: %d\n", len(result.Differences)))
		sb.WriteString("---\n")
		for i, diff := range result.Differences {
			if i >= 10 {
				sb.WriteString(fmt.Sprintf("... and %d more differences\n", len(result.Differences)-10))
				break
			}
			sb.WriteString(fmt.Sprintf("Packet %d, Layer %s, Field %s:\n", diff.PacketIndex, diff.Layer, diff.Field))
			sb.WriteString(fmt.Sprintf("  Input:  %v\n", diff.File1Value))
			sb.WriteString(fmt.Sprintf("  Output: %v\n", diff.File2Value))
		}
	}

	sb.WriteString(fmt.Sprintf("\nTimestamp: %s\n", time.Now().Format(time.RFC3339)))

	return sb.String()
}

// Helper functions to extract config values

func getVXLANPort(config map[string]interface{}) int {
	if vxlan, ok := config["vxlan"].(map[string]interface{}); ok {
		if port, ok := vxlan["port"].(float64); ok {
			return int(port)
		}
	}
	return 4789 // Default VXLAN port
}

func getZMQEndpoint(config map[string]interface{}) string {
	if zmq, ok := config["zmq"].(map[string]interface{}); ok {
		if host, ok := zmq["host"].(string); ok {
			if port, ok := zmq["port"].(float64); ok {
				return fmt.Sprintf("tcp://%s:%d", host, int(port))
			}
		}
	}
	return "tcp://127.0.0.1:9002" // Default
}

func getFileOutputPath(config map[string]interface{}) string {
	if file, ok := config["file"].(map[string]interface{}); ok {
		if name, ok := file["name"].(string); ok {
			return name
		}
	}
	return "" // Default
}
