package helpers

import (
	"encoding/json"
	"fmt"
	"os"
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
)

// VerifyConfig defines the verification configuration
type VerifyConfig struct {
	Rule            VerifyRule `json:"rule"`
	MinPackets      int        `json:"min_packets,omitempty"`
	MaxPackets      int        `json:"max_packets,omitempty"`
	IgnoreTimestamp bool       `json:"ignore_timestamp"`
	ValidateLayers  []string   `json:"validate_layers,omitempty"`
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

	// Set defaults
	if config.Rule == "" {
		config.Rule = RulePacketCountOnly
	}
	if config.Rule == RuleExactMatch && !config.IgnoreTimestamp {
		config.IgnoreTimestamp = true // Default to ignoring timestamp
	}

	return &config, nil
}

// Verify performs verification based on the config
func Verify(inputPCAP, outputPCAP string, config *VerifyConfig) (*VerifyResult, error) {
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

	default:
		return nil, fmt.Errorf("unknown verify rule: %s", config.Rule)
	}

	return result, nil
}
