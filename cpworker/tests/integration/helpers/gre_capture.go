package helpers

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// GRECapturer captures GRE encapsulated packets
type GRECapturer struct {
	iface      string
	handle     *pcap.Handle
	writer     *pcapgo.Writer
	outputFile *os.File
	stopChan   chan struct{}
	doneChan   chan struct{}
	stopOnce   sync.Once
}

// NewGRECapturer creates a new GRE capturer
func NewGRECapturer(iface string, outputPath string) (*GRECapturer, error) {
	// Open output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	// Create pcap writer
	writer := pcapgo.NewWriter(outputFile)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		outputFile.Close()
		return nil, fmt.Errorf("failed to write pcap header: %w", err)
	}

	return &GRECapturer{
		iface:      iface,
		writer:     writer,
		outputFile: outputFile,
		stopChan:   make(chan struct{}),
		doneChan:   make(chan struct{}),
	}, nil
}

// Start starts capturing GRE packets
func (g *GRECapturer) Start() error {
	// Open network interface for capturing with timeout to allow checking stopChan
	handle, err := pcap.OpenLive(g.iface, 65536, true, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", g.iface, err)
	}
	g.handle = handle

	// Set BPF filter for GRE traffic (IP protocol 47)
	filter := "ip proto 47"
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	// Start capture loop in goroutine
	go g.captureLoop()

	return nil
}

// captureLoop is the main packet capture loop
func (g *GRECapturer) captureLoop() {
	defer close(g.doneChan)

	packetSource := gopacket.NewPacketSource(g.handle, g.handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-g.stopChan:
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			// Write the complete packet (Ethernet + IP + GRE + inner frame)
			g.writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
	}
}

// Stop stops the capturer. Safe to call multiple times.
func (g *GRECapturer) Stop() error {
	g.stopOnce.Do(func() {
		close(g.stopChan)

		// Wait for capture loop to finish with timeout
		select {
		case <-g.doneChan:
		case <-time.After(5 * time.Second):
			// Timeout
		}

		if g.handle != nil {
			g.handle.Close()
		}

		if g.outputFile != nil {
			g.outputFile.Close()
		}
	})

	return nil
}

// WaitForPackets waits for at least one packet to be captured
func (g *GRECapturer) WaitForPackets(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		count, err := CountPackets(g.outputFile.Name())
		if err == nil && count > 0 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for packets")
}
