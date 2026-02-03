package helpers

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"os"
)

// VXLANCapturer captures VXLAN encapsulated packets
type VXLANCapturer struct {
	iface      string
	port       int
	handle     *pcap.Handle
	writer     *pcapgo.Writer
	outputFile *os.File
	stopChan   chan struct{}
	doneChan   chan struct{}
}

// NewVXLANCapturer creates a new VXLAN capturer
func NewVXLANCapturer(iface string, port int, outputPath string) (*VXLANCapturer, error) {
	if port == 0 {
		port = 4789 // Default VXLAN port
	}

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

	return &VXLANCapturer{
		iface:      iface,
		port:       port,
		writer:     writer,
		outputFile: outputFile,
		stopChan:   make(chan struct{}),
		doneChan:   make(chan struct{}),
	}, nil
}

// Start starts capturing VXLAN packets
func (v *VXLANCapturer) Start() error {
	// Open network interface for capturing with timeout to allow checking stopChan
	handle, err := pcap.OpenLive(v.iface, 65536, true, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", v.iface, err)
	}
	v.handle = handle

	// Set BPF filter for VXLAN traffic
	filter := fmt.Sprintf("udp port %d", v.port)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	// Start capture loop in goroutine
	go v.captureLoop()

	return nil
}

// captureLoop is the main packet capture loop
func (v *VXLANCapturer) captureLoop() {
	defer close(v.doneChan)

	packetSource := gopacket.NewPacketSource(v.handle, v.handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-v.stopChan:
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			// Write the complete packet (Ethernet + IP + UDP + VXLAN + inner frame)
			v.writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
	}
}

// Stop stops the capturer
func (v *VXLANCapturer) Stop() error {
	close(v.stopChan)

	// Wait for capture loop to finish with timeout
	select {
	case <-v.doneChan:
	case <-time.After(5 * time.Second):
		// Timeout
	}

	if v.handle != nil {
		v.handle.Close()
	}

	if v.outputFile != nil {
		v.outputFile.Close()
	}

	return nil
}

// WaitForPackets waits for at least one packet to be captured
func (v *VXLANCapturer) WaitForPackets(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		count, err := CountPackets(v.outputFile.Name())
		if err == nil && count > 0 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for packets")
}
