package helpers

import (
	"fmt"
	"reflect"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// CompareOptions defines options for PCAP comparison
type CompareOptions struct {
	IgnoreTimestamp    bool
	AllowPacketSplit   bool
	AllowSlice         bool
	MaxPacketCountDiff int
	ValidateLayers     []string
}

// PacketDifference represents a difference between two packets
type PacketDifference struct {
	PacketIndex int
	Layer       string
	Field       string
	File1Value  interface{}
	File2Value  interface{}
}

// CountPackets counts the number of packets in a PCAP file, excluding heartbeat packets.
func CountPackets(pcapFile string) (int, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return 0, fmt.Errorf("failed to open pcap file %s: %w", pcapFile, err)
	}
	defer handle.Close()

	count := 0
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if !isHeartbeatPacket(packet.Data()) {
			count++
		}
	}

	return count, nil
}

// isHeartbeatPacket detects ZMQ heartbeat packets.
// Heartbeat: 14-byte Ethernet frame with all-zero MACs and EtherType=0xFFFF.
func isHeartbeatPacket(data []byte) bool {
	if len(data) != 14 {
		return false
	}
	for i := 0; i < 12; i++ {
		if data[i] != 0 {
			return false
		}
	}
	return data[12] == 0xFF && data[13] == 0xFF
}

// ComparePCAPsExact compares two PCAP files packet by packet
func ComparePCAPsExact(file1, file2 string, opts CompareOptions) ([]PacketDifference, error) {
	handle1, err := pcap.OpenOffline(file1)
	if err != nil {
		return nil, fmt.Errorf("failed to open first pcap file: %w", err)
	}
	defer handle1.Close()

	handle2, err := pcap.OpenOffline(file2)
	if err != nil {
		return nil, fmt.Errorf("failed to open second pcap file: %w", err)
	}
	defer handle2.Close()

	var differences []PacketDifference

	packetSource1 := gopacket.NewPacketSource(handle1, handle1.LinkType())
	packetSource2 := gopacket.NewPacketSource(handle2, handle2.LinkType())

	packets1 := packetSource1.Packets()
	packets2 := packetSource2.Packets()

	packetIndex := 0
	for {
		pkt1, ok1 := <-packets1
		pkt2, ok2 := <-packets2

		// Both exhausted
		if !ok1 && !ok2 {
			break
		}

		// Different number of packets
		if ok1 != ok2 {
			if !ok1 {
				differences = append(differences, PacketDifference{
					PacketIndex: packetIndex,
					Layer:       "PacketCount",
					Field:       "EOF",
					File1Value:  "EOF reached",
					File2Value:  "More packets available",
				})
			} else {
				differences = append(differences, PacketDifference{
					PacketIndex: packetIndex,
					Layer:       "PacketCount",
					Field:       "EOF",
					File1Value:  "More packets available",
					File2Value:  "EOF reached",
				})
			}
			break
		}

		// Compare packet data
		diffs := comparePackets(pkt1, pkt2, packetIndex, opts)
		differences = append(differences, diffs...)

		packetIndex++
	}

	return differences, nil
}

// comparePackets compares two individual packets
func comparePackets(pkt1, pkt2 gopacket.Packet, index int, opts CompareOptions) []PacketDifference {
	var differences []PacketDifference

	// Compare packet length if not allowing slice
	if !opts.AllowSlice {
		if len(pkt1.Data()) != len(pkt2.Data()) {
			differences = append(differences, PacketDifference{
				PacketIndex: index,
				Layer:       "Packet",
				Field:       "Length",
				File1Value:  len(pkt1.Data()),
				File2Value:  len(pkt2.Data()),
			})
		}
	}

	// If specific layers to validate are specified
	if len(opts.ValidateLayers) > 0 {
		for _, layerName := range opts.ValidateLayers {
			diffs := compareLayer(pkt1, pkt2, index, layerName, opts)
			differences = append(differences, diffs...)
		}
	} else {
		// Compare all common layers
		diffs := compareAllLayers(pkt1, pkt2, index, opts)
		differences = append(differences, diffs...)
	}

	return differences
}

// compareAllLayers compares all layers in the packets
func compareAllLayers(pkt1, pkt2 gopacket.Packet, index int, opts CompareOptions) []PacketDifference {
	var differences []PacketDifference

	// Get all layers from both packets
	layers1 := pkt1.Layers()
	layers2 := pkt2.Layers()

	if len(layers1) != len(layers2) {
		differences = append(differences, PacketDifference{
			PacketIndex: index,
			Layer:       "LayerCount",
			Field:       "Count",
			File1Value:  len(layers1),
			File2Value:  len(layers2),
		})
		return differences
	}

	// Compare each layer
	for i := range layers1 {
		if layers1[i].LayerType() != layers2[i].LayerType() {
			differences = append(differences, PacketDifference{
				PacketIndex: index,
				Layer:       fmt.Sprintf("Layer[%d]", i),
				Field:       "LayerType",
				File1Value:  layers1[i].LayerType().String(),
				File2Value:  layers2[i].LayerType().String(),
			})
			continue
		}

		// Compare layer contents (excluding timestamp for certain layers)
		if !layerContentsEqual(layers1[i], layers2[i], opts) {
			differences = append(differences, PacketDifference{
				PacketIndex: index,
				Layer:       layers1[i].LayerType().String(),
				Field:       "Contents",
				File1Value:  fmt.Sprintf("%x", layers1[i].LayerContents()[:min(32, len(layers1[i].LayerContents()))]),
				File2Value:  fmt.Sprintf("%x", layers2[i].LayerContents()[:min(32, len(layers2[i].LayerContents()))]),
			})
		}
	}

	return differences
}

// compareLayer compares a specific layer between two packets
func compareLayer(pkt1, pkt2 gopacket.Packet, index int, layerName string, opts CompareOptions) []PacketDifference {
	var differences []PacketDifference

	var layer1, layer2 gopacket.Layer

	// Find the layer in both packets
	switch layerName {
	case "Ethernet":
		layer1 = pkt1.Layer(layers.LayerTypeEthernet)
		layer2 = pkt2.Layer(layers.LayerTypeEthernet)
	case "IPv4":
		layer1 = pkt1.Layer(layers.LayerTypeIPv4)
		layer2 = pkt2.Layer(layers.LayerTypeIPv4)
	case "IPv6":
		layer1 = pkt1.Layer(layers.LayerTypeIPv6)
		layer2 = pkt2.Layer(layers.LayerTypeIPv6)
	case "TCP":
		layer1 = pkt1.Layer(layers.LayerTypeTCP)
		layer2 = pkt2.Layer(layers.LayerTypeTCP)
	case "UDP":
		layer1 = pkt1.Layer(layers.LayerTypeUDP)
		layer2 = pkt2.Layer(layers.LayerTypeUDP)
	default:
		// Layer not recognized
		return differences
	}

	// Check if layer exists in both packets
	if (layer1 == nil) != (layer2 == nil) {
		differences = append(differences, PacketDifference{
			PacketIndex: index,
			Layer:       layerName,
			Field:       "Exists",
			File1Value:  layer1 != nil,
			File2Value:  layer2 != nil,
		})
		return differences
	}

	// If layer doesn't exist in both, that's fine
	if layer1 == nil {
		return differences
	}

	// Compare layer contents
	if !layerContentsEqual(layer1, layer2, opts) {
		differences = append(differences, PacketDifference{
			PacketIndex: index,
			Layer:       layerName,
			Field:       "Contents",
			File1Value:  fmt.Sprintf("%x", layer1.LayerContents()[:min(32, len(layer1.LayerContents()))]),
			File2Value:  fmt.Sprintf("%x", layer2.LayerContents()[:min(32, len(layer2.LayerContents()))]),
		})
	}

	return differences
}

// layerContentsEqual checks if layer contents are equal
func layerContentsEqual(layer1, layer2 gopacket.Layer, opts CompareOptions) bool {
	// For now, do a simple byte comparison
	// In the future, we could add more sophisticated comparison that ignores certain fields
	contents1 := layer1.LayerContents()
	contents2 := layer2.LayerContents()

	return reflect.DeepEqual(contents1, contents2)
}
