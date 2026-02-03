package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	zmq "github.com/pebbe/zmq4"
)

// ZMQ message format structures (from cptools/recvzmq/main.c)
type zmqPktBatchHdr struct {
	Version uint16
	PktsNum uint16
	Keybit  uint32
	UUID    [16]byte
}

type zmqPktHdr struct {
	TvSec  uint32
	TvUsec uint32
	Caplen uint32
	Len    uint32
}

// ZMQStats contains statistics about captured ZMQ messages
type ZMQStats struct {
	MessageCount     int       `json:"message_count"`
	PacketCount      int       `json:"packet_count"`
	TotalBytes       int64     `json:"total_bytes"`
	AvgPacketsPerMsg float64   `json:"avg_packets_per_message"`
	FirstTimestamp   time.Time `json:"first_timestamp,omitempty"`
	LastTimestamp    time.Time `json:"last_timestamp,omitempty"`
}

func main() {
	endpoint := flag.String("endpoint", "tcp://127.0.0.1:9002", "ZMQ endpoint to bind")
	pcapFile := flag.String("pcap", "output.pcap", "Output pcap file")
	rawFile := flag.String("raw", "output.raw", "Output raw message file")
	statsFile := flag.String("stats", "stats.json", "Output stats JSON file")
	flag.Parse()

	fmt.Fprintf(os.Stderr, "[zmq_receiver] Starting on endpoint: %s\n", *endpoint)
	fmt.Fprintf(os.Stderr, "[zmq_receiver] PCAP output: %s\n", *pcapFile)
	fmt.Fprintf(os.Stderr, "[zmq_receiver] Raw output: %s\n", *rawFile)

	// Create ZMQ PULL socket
	socket, err := zmq.NewSocket(zmq.PULL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[zmq_receiver] Failed to create ZMQ socket: %v\n", err)
		os.Exit(1)
	}
	defer socket.Close()

	// Bind to endpoint
	if err := socket.Bind(*endpoint); err != nil {
		fmt.Fprintf(os.Stderr, "[zmq_receiver] Failed to bind to %s: %v\n", *endpoint, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[zmq_receiver] Successfully bound to %s\n", *endpoint)

	// Set receive timeout
	socket.SetRcvtimeo(100 * time.Millisecond)

	// Open raw output file
	rawOut, err := os.Create(*rawFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[zmq_receiver] Failed to create raw file: %v\n", err)
		os.Exit(1)
	}
	defer rawOut.Close()

	// Open pcap output file
	pcapOut, err := os.Create(*pcapFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[zmq_receiver] Failed to create pcap file: %v\n", err)
		os.Exit(1)
	}
	defer pcapOut.Close()

	// Create pcap writer
	pcapWriter := pcapgo.NewWriter(pcapOut)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		fmt.Fprintf(os.Stderr, "[zmq_receiver] Failed to write pcap header: %v\n", err)
		os.Exit(1)
	}

	stats := &ZMQStats{}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Fprintf(os.Stderr, "[zmq_receiver] Ready to receive messages...\n")

	// Main receive loop
	running := true
	for running {
		select {
		case <-sigChan:
			fmt.Fprintf(os.Stderr, "[zmq_receiver] Received signal, shutting down...\n")
			running = false
			continue
		default:
		}

		// Receive ZMQ message
		msgData, err := socket.RecvBytes(0)
		if err != nil {
			// Timeout or error, continue
			continue
		}

		// Save raw message
		if err := saveRawMessage(rawOut, msgData); err != nil {
			fmt.Fprintf(os.Stderr, "[zmq_receiver] Failed to save raw message: %v\n", err)
			continue
		}

		// Parse and extract packets
		if err := parseAndExtractPackets(pcapWriter, msgData, stats); err != nil {
			fmt.Fprintf(os.Stderr, "[zmq_receiver] Failed to parse ZMQ message: %v\n", err)
			continue
		}

		stats.MessageCount++
		stats.TotalBytes += int64(len(msgData))
	}

	// Save stats
	if stats.MessageCount > 0 {
		stats.AvgPacketsPerMsg = float64(stats.PacketCount) / float64(stats.MessageCount)
	}

	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[zmq_receiver] Failed to marshal stats: %v\n", err)
	} else {
		if err := os.WriteFile(*statsFile, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "[zmq_receiver] Failed to write stats: %v\n", err)
		}
	}

	fmt.Fprintf(os.Stderr, "[zmq_receiver] Shutdown complete. Messages: %d, Packets: %d\n", stats.MessageCount, stats.PacketCount)
}

func saveRawMessage(rawFile *os.File, msgData []byte) error {
	// Write message length (4 bytes)
	length := uint32(len(msgData))
	if err := binary.Write(rawFile, binary.BigEndian, length); err != nil {
		return err
	}

	// Write message data
	_, err := rawFile.Write(msgData)
	return err
}

func parseAndExtractPackets(pcapWriter *pcapgo.Writer, msgData []byte, stats *ZMQStats) error {
	if len(msgData) < 20 {
		return fmt.Errorf("message too short: %d bytes", len(msgData))
	}

	// Parse batch header
	var batchHdr zmqPktBatchHdr
	batchHdr.Version = binary.BigEndian.Uint16(msgData[0:2])
	batchHdr.PktsNum = binary.BigEndian.Uint16(msgData[2:4])
	batchHdr.Keybit = binary.BigEndian.Uint32(msgData[4:8])
	copy(batchHdr.UUID[:], msgData[8:24])

	offset := 24 // sizeof(zmq_pkt_batch_hdr_t)

	// Extract each packet
	for i := 0; i < int(batchHdr.PktsNum); i++ {
		if offset+2 > len(msgData) {
			return fmt.Errorf("unexpected end of message at packet %d", i)
		}

		// Read packet data length (2 bytes)
		pktDataLen := int(binary.BigEndian.Uint16(msgData[offset : offset+2]))
		offset += 2

		if offset+16 > len(msgData) {
			return fmt.Errorf("unexpected end of message reading packet header %d", i)
		}

		// Read packet header
		var pktHdr zmqPktHdr
		pktHdr.TvSec = binary.BigEndian.Uint32(msgData[offset : offset+4])
		pktHdr.TvUsec = binary.BigEndian.Uint32(msgData[offset+4 : offset+8])
		pktHdr.Caplen = binary.BigEndian.Uint32(msgData[offset+8 : offset+12])
		pktHdr.Len = binary.BigEndian.Uint32(msgData[offset+12 : offset+16])
		offset += 16

		if offset+pktDataLen > len(msgData) {
			return fmt.Errorf("unexpected end of message reading packet data %d", i)
		}

		// Read packet data (already complete Ethernet frame)
		pktData := msgData[offset : offset+pktDataLen]
		offset += pktDataLen

		// Write to pcap file
		timestamp := time.Unix(int64(pktHdr.TvSec), int64(pktHdr.TvUsec)*1000)
		captureInfo := gopacket.CaptureInfo{
			Timestamp:     timestamp,
			CaptureLength: int(pktHdr.Caplen),
			Length:        int(pktHdr.Len),
		}

		if err := pcapWriter.WritePacket(captureInfo, pktData); err != nil {
			return fmt.Errorf("failed to write packet to pcap: %w", err)
		}

		stats.PacketCount++

		// Update timestamp stats
		if stats.FirstTimestamp.IsZero() {
			stats.FirstTimestamp = timestamp
		}
		stats.LastTimestamp = timestamp
	}

	return nil
}
