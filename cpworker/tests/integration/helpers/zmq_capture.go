package helpers

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// ZMQCapturer captures ZMQ messages using an external receiver process
type ZMQCapturer struct {
	endpoint    string
	rawFile     string
	pcapFile    string
	statsFile   string
	cmd         *exec.Cmd
	receiverBin string
	stats       *ZMQStats
	stopOnce    sync.Once
}

// ZMQStats contains statistics about captured ZMQ messages
type ZMQStats struct {
	MessageCount     int       `json:"message_count"`
	PacketCount      int       `json:"packet_count"`
	HeartbeatCount   int       `json:"heartbeat_count"`
	TotalBytes       int64     `json:"total_bytes"`
	AvgPacketsPerMsg float64   `json:"avg_packets_per_message"`
	FirstTimestamp   time.Time `json:"first_timestamp,omitempty"`
	LastTimestamp    time.Time `json:"last_timestamp,omitempty"`
}

// NewZMQCapturer creates a new ZMQ capturer (does not create any ZMQ sockets in this process)
func NewZMQCapturer(endpoint string, rawOutputPath, pcapOutputPath, statsOutputPath, receiverSrcDir string) (*ZMQCapturer, error) {
	// Determine path to zmq_receiver binary
	// First, try to build it
	receiverBin := filepath.Join(receiverSrcDir, "zmq_receiver")

	// Check if source exists
	if _, err := os.Stat(receiverSrcDir); err != nil {
		return nil, fmt.Errorf("zmq_receiver source not found at %s: %w", receiverSrcDir, err)
	}

	// Build the receiver if not already built or outdated
	mainGo := filepath.Join(receiverSrcDir, "main.go")
	needsBuild := false

	if binStat, err := os.Stat(receiverBin); err != nil {
		needsBuild = true
	} else if srcStat, err := os.Stat(mainGo); err == nil {
		// Rebuild if source is newer than binary
		if srcStat.ModTime().After(binStat.ModTime()) {
			needsBuild = true
		}
	}

	if needsBuild {
		fmt.Fprintf(os.Stderr, "[ZMQCapturer] Building zmq_receiver...\n")
		buildCmd := exec.Command("go", "build", "-o", "zmq_receiver", ".")
		buildCmd.Dir = receiverSrcDir
		buildCmd.Stdout = os.Stderr
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to build zmq_receiver: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[ZMQCapturer] zmq_receiver built successfully\n")
	}

	return &ZMQCapturer{
		endpoint:    endpoint,
		rawFile:     rawOutputPath,
		pcapFile:    pcapOutputPath,
		statsFile:   statsOutputPath,
		receiverBin: receiverBin,
		stats:       &ZMQStats{},
	}, nil
}

// Start starts the ZMQ receiver process
func (z *ZMQCapturer) Start() error {
	// Start zmq_receiver as external process
	z.cmd = exec.Command(
		z.receiverBin,
		"-endpoint", z.endpoint,
		"-pcap", z.pcapFile,
		"-raw", z.rawFile,
		"-stats", z.statsFile,
	)

	// Capture stderr for debugging
	z.cmd.Stderr = os.Stderr

	fmt.Fprintf(os.Stderr, "[ZMQCapturer] Starting zmq_receiver: %s -endpoint %s -pcap %s\n",
		z.receiverBin, z.endpoint, z.pcapFile)

	if err := z.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start zmq_receiver: %w", err)
	}

	// Give receiver time to bind
	time.Sleep(200 * time.Millisecond)

	fmt.Fprintf(os.Stderr, "[ZMQCapturer] zmq_receiver started (PID: %d)\n", z.cmd.Process.Pid)
	return nil
}

// Stop stops the ZMQ receiver process. Safe to call multiple times.
func (z *ZMQCapturer) Stop() error {
	z.stopOnce.Do(func() {
		if z.cmd == nil || z.cmd.Process == nil {
			return
		}

		fmt.Fprintf(os.Stderr, "[ZMQCapturer] Stopping zmq_receiver (PID: %d)...\n", z.cmd.Process.Pid)

		// Send SIGTERM for graceful shutdown
		if err := z.cmd.Process.Signal(os.Interrupt); err != nil {
			// If signal fails, try kill
			z.cmd.Process.Kill()
		}

		// Wait for process to exit (with timeout)
		done := make(chan error, 1)
		go func() {
			done <- z.cmd.Wait()
		}()

		select {
		case <-done:
			// Process exited
		case <-time.After(3 * time.Second):
			// Timeout, force kill
			z.cmd.Process.Kill()
			z.cmd.Wait()
		}

		fmt.Fprintf(os.Stderr, "[ZMQCapturer] zmq_receiver stopped\n")
	})
	return nil
}

// GetStats returns the current statistics (reads from file)
func (z *ZMQCapturer) GetStats() *ZMQStats {
	data, err := os.ReadFile(z.statsFile)
	if err != nil {
		return z.stats
	}

	var stats ZMQStats
	if err := json.Unmarshal(data, &stats); err != nil {
		return z.stats
	}

	z.stats = &stats
	return z.stats
}

// WaitForPackets waits for at least one packet to be captured
func (z *ZMQCapturer) WaitForPackets(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		stats := z.GetStats()
		if stats.PacketCount > 0 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for packets")
}
