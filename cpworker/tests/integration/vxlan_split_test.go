package integration

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/netis-cloud-probe/cloud-probe/cpworker/tests/integration/helpers"
)

const (
	splitVXLANPort  = 4795
	splitMaxPayload = 600
	vxlanHeaderLen  = 8
)

// buildFragmentedUDP returns one UDP datagram carrying payloadLen bytes, cut
// into IPv4 fragments of at most mtu bytes as a router would (RFC 791), each
// wrapped in an Ethernet frame.
func buildFragmentedUDP(t *testing.T, payloadLen, mtu int) [][]byte {
	t.Helper()
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	data := make([]byte, payloadLen)
	for i := range data {
		data[i] = byte(i*7 + 3)
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
	udp := &layers.UDP{SrcPort: 5000, DstPort: 6000}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set checksum layer: %v", err)
	}
	datagramBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(datagramBuf, opts, udp, gopacket.Payload(data)); err != nil {
		t.Fatalf("serialize udp: %v", err)
	}
	datagram := datagramBuf.Bytes()

	fragPayloadLen := (mtu - 20) &^ 7
	var frames [][]byte
	for off := 0; off < len(datagram); off += fragPayloadLen {
		end := off + fragPayloadLen
		flags := layers.IPv4MoreFragments
		if end >= len(datagram) {
			end = len(datagram)
			flags = 0
		}
		frag := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Id: 0x4242, Flags: flags, FragOffset: uint16(off / 8),
			Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeIPv4}
		frameBuf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(frameBuf, opts, eth, frag, gopacket.Payload(datagram[off:end])); err != nil {
			t.Fatalf("serialize fragment: %v", err)
		}
		frames = append(frames, append([]byte(nil), frameBuf.Bytes()...))
	}
	return frames
}

func writeEthernetPcap(t *testing.T, path string, frames [][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	ts := time.Unix(1700000000, 0)
	for i, fr := range frames {
		ci := gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Millisecond), CaptureLength: len(fr), Length: len(fr)}
		if err := w.WritePacket(ci, fr); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
}

// innerFrames strips the outer Ethernet/IPv4/UDP/VXLAN headers from captured VXLAN packets.
func innerFrames(captured [][]byte) [][]byte {
	var out [][]byte
	for _, pkt := range captured {
		p := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
		udp, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok || int(udp.DstPort) != splitVXLANPort || len(udp.Payload) < vxlanHeaderLen {
			continue
		}
		out = append(out, udp.Payload[vxlanHeaderLen:])
	}
	return out
}

// TestVXLANSplitIPv4Fragments sends a fragmented UDP datagram through a vxlan
// output with split enabled. The fragments are larger than max_payload_size,
// but a fragment carries only part of the datagram and cannot be split at L4,
// so each must arrive unchanged (issue #244). Before the fix, split parsed
// fragment payload as a TCP/UDP header and rewrote it.
func TestVXLANSplitIPv4Fragments(t *testing.T) {
	if os.Getenv("CPWORKER_BIN") == "" {
		t.Skip("CPWORKER_BIN not set")
	}

	out := setupTestOutputDir(t, "vxlan_split_ipv4_fragments")
	frames := buildFragmentedUDP(t, 3000, 1500)
	if len(frames) != 3 {
		t.Fatalf("built %d fragments, want 3", len(frames))
	}
	input := filepath.Join(out, "input.pcap")
	writeEthernetPcap(t, input, frames)

	cfg, err := json.MarshalIndent(map[string]any{
		"tasks": []map[string]any{{
			"capturer": map[string]any{"type": "pcap_file", "pcap_file": map[string]any{"file_name": input}},
			"outputs": []map[string]any{{"type": "vxlan", "vxlan": map[string]any{
				"host": "127.0.0.1", "port": splitVXLANPort, "vni1": 100,
				"split": map[string]any{"max_payload_size": splitMaxPayload, "recalculate_checksum": true},
			}}},
		}},
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	conf := filepath.Join(out, "config.json")
	if err := os.WriteFile(conf, cfg, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	capPath := filepath.Join(out, "vxlan_capture.pcap")
	capturer, err := helpers.NewVXLANCapturer("lo", splitVXLANPort, capPath)
	if err != nil {
		t.Fatalf("new vxlan capturer: %v", err)
	}
	if err := capturer.Start(); err != nil {
		t.Fatalf("start vxlan capturer: %v", err)
	}
	defer capturer.Stop()
	time.Sleep(500 * time.Millisecond)

	runner, logp, _ := startReloadWorker(t, out, conf)
	if !waitForAnyLog(logp, []string{pcapFileEOFLog}, 5*time.Second) {
		t.Fatalf("worker never finished reading the file; log:\n%s", readLog(logp))
	}
	time.Sleep(500 * time.Millisecond)
	if err := runner.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}
	if !runner.WaitExit(5 * time.Second) {
		t.Fatalf("worker did not exit; log:\n%s", readLog(logp))
	}
	capturer.Stop()

	inner := innerFrames(readPcapData(t, capPath))
	if len(inner) != len(frames) {
		t.Fatalf("got %d inner frames, want %d (fragments must not be split)", len(inner), len(frames))
	}
	for i := range frames {
		if !bytes.Equal(inner[i], frames[i]) {
			t.Errorf("inner frame %d differs from input fragment %d", i, i)
		}
	}
}
