package helpers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VerifyRule defines the type of verification to perform
type VerifyRule string

const (
	// RulePacketCountOnly verifies only packet count matches
	RulePacketCountOnly VerifyRule = "packet_count_only"
	// RuleExactMatch verifies packets match exactly (except timestamp)
	RuleExactMatch VerifyRule = "exact_match"
	// RulePacketCountRange verifies packet count is within range
	RulePacketCountRange VerifyRule = "packet_count_range"
	// RuleNoVerify skips verification, only saves output
	RuleNoVerify VerifyRule = "no_verify"
	// RuleZMQHeartbeat verifies heartbeat packets were generated
	RuleZMQHeartbeat VerifyRule = "zmq_heartbeat"
)

// VerifyRuleConfig defines a single verification rule configuration
type VerifyRuleConfig struct {
	Rule            VerifyRule `json:"rule"`
	MinPackets      int        `json:"min_packets,omitempty"`
	MaxPackets      int        `json:"max_packets,omitempty"`
	IgnoreTimestamp bool       `json:"ignore_timestamp"`
	ValidateLayers  []string   `json:"validate_layers,omitempty"`
}

// VerifyConfig defines the top-level verification configuration with multiple rules
type VerifyConfig struct {
	Rules []*VerifyRuleConfig `json:"rules"`
}

// VerifyResult contains the verification results
type VerifyResult struct {
	Passed        bool
	InputPackets  int
	OutputPackets int
	Message       string
	Differences   []PacketDifference
}

// LoadVerifyConfig loads verification config from JSON file
func LoadVerifyConfig(path string) (*VerifyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read verify config: %w", err)
	}

	var config VerifyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse verify config: %w", err)
	}

	// Set defaults for each rule
	for _, rule := range config.Rules {
		if rule.Rule == "" {
			rule.Rule = RulePacketCountOnly
		}
		if rule.Rule == RuleExactMatch && !rule.IgnoreTimestamp {
			rule.IgnoreTimestamp = true
		}
	}

	return &config, nil
}

// Verify performs verification based on the config, running all rules (AND logic)
func Verify(inputPCAP, outputPCAP string, config *VerifyConfig) (*VerifyResult, error) {
	if len(config.Rules) == 0 {
		return &VerifyResult{Passed: true, Message: "No rules configured"}, nil
	}

	var messages []string
	var allDiffs []PacketDifference
	allPassed := true
	var inputPackets, outputPackets int

	for i, rule := range config.Rules {
		result, err := verifySingleRule(inputPCAP, outputPCAP, rule)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i, rule.Rule, err)
		}

		if i == 0 {
			inputPackets = result.InputPackets
			outputPackets = result.OutputPackets
		}

		if !result.Passed {
			allPassed = false
		}
		messages = append(messages, result.Message)
		allDiffs = append(allDiffs, result.Differences...)
	}

	return &VerifyResult{
		Passed:        allPassed,
		InputPackets:  inputPackets,
		OutputPackets: outputPackets,
		Message:       strings.Join(messages, "; "),
		Differences:   allDiffs,
	}, nil
}

// verifySingleRule performs verification for a single rule
func verifySingleRule(inputPCAP, outputPCAP string, config *VerifyRuleConfig) (*VerifyResult, error) {
	result := &VerifyResult{}

	// Count input packets
	inputCount, err := CountPackets(inputPCAP)
	if err != nil {
		return nil, fmt.Errorf("failed to count input packets: %w", err)
	}
	result.InputPackets = inputCount

	// Count output packets
	outputCount, err := CountPackets(outputPCAP)
	if err != nil {
		return nil, fmt.Errorf("failed to count output packets: %w", err)
	}
	result.OutputPackets = outputCount

	switch config.Rule {
	case RuleNoVerify:
		result.Passed = true
		result.Message = "No verification performed (rule: no_verify)"
		return result, nil

	case RulePacketCountOnly:
		if inputCount == outputCount {
			result.Passed = true
			result.Message = fmt.Sprintf("Packet count match: %d packets", inputCount)
		} else {
			result.Passed = false
			result.Message = fmt.Sprintf("Packet count mismatch: input=%d, output=%d", inputCount, outputCount)
		}

	case RulePacketCountRange:
		if outputCount >= config.MinPackets && outputCount <= config.MaxPackets {
			result.Passed = true
			result.Message = fmt.Sprintf("Packet count in range [%d-%d]: %d packets",
				config.MinPackets, config.MaxPackets, outputCount)
		} else {
			result.Passed = false
			result.Message = fmt.Sprintf("Packet count out of range [%d-%d]: %d packets",
				config.MinPackets, config.MaxPackets, outputCount)
		}

	case RuleExactMatch:
		opts := CompareOptions{
			IgnoreTimestamp: config.IgnoreTimestamp,
		}

		// Convert layer names to LayerTypes if specified
		if len(config.ValidateLayers) > 0 {
			opts.ValidateLayers = config.ValidateLayers
		}

		diffs, err := ComparePCAPsExact(inputPCAP, outputPCAP, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to compare PCAPs: %w", err)
		}

		result.Differences = diffs
		if len(diffs) == 0 {
			result.Passed = true
			result.Message = fmt.Sprintf("Packets match exactly: %d packets", inputCount)
		} else {
			result.Passed = false
			result.Message = fmt.Sprintf("Found %d differences in %d packets", len(diffs), inputCount)
		}

	case RuleZMQHeartbeat:
		// Verify heartbeat packets were generated by reading zmq_stats.json
		statsFile := filepath.Join(filepath.Dir(outputPCAP), "zmq_stats.json")
		statsData, err := os.ReadFile(statsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read zmq stats file: %w", err)
		}

		var zmqStats ZMQStats
		if err := json.Unmarshal(statsData, &zmqStats); err != nil {
			return nil, fmt.Errorf("failed to parse zmq stats: %w", err)
		}

		// Check heartbeat count meets minimum
		minHeartbeats := config.MinPackets
		if minHeartbeats <= 0 {
			minHeartbeats = 1
		}

		if zmqStats.HeartbeatCount >= minHeartbeats {
			result.Passed = true
			result.Message = fmt.Sprintf("Heartbeat check passed: %d heartbeats (min: %d)",
				zmqStats.HeartbeatCount, minHeartbeats)
		} else {
			result.Passed = false
			result.Message = fmt.Sprintf("Heartbeat check failed: %d heartbeats (min: %d)",
				zmqStats.HeartbeatCount, minHeartbeats)
		}

	default:
		return nil, fmt.Errorf("unknown verify rule: %s", config.Rule)
	}

	return result, nil
}
