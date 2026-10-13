package integration

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/netis-cloud-probe/cloud-probe/cpworker/tests/integration/helpers"
)

const (
	wireVXLANPort      = 4796
	wireZMQPort        = 19004
	wireZMQExamplePort = 19005

	// wireReqPattern makes a frame to TCP port 80 INCOMING and one from port 80 OUTGOING.
	wireReqPattern = "port 80"
	wireTsSec      = 1700000000
)

// wirePacket is one pcap record: the captured bytes, the timestamp and the original length.
type wirePacket struct {
	data    []byte
	sec     uint32
	usec    uint32
	origLen int
}

// wireTask is one cpworker task reading its own pcap file into a single output.
type wireTask struct {
	input      []wirePacket
	reqPattern bool
	output     map[string]any
}

// unhex decodes a hex string that may contain spaces.
func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func be16(v int) []byte {
	return binary.BigEndian.AppendUint16(nil, uint16(v))
}

func be32(v uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, v)
}

// wireFrame returns an Ethernet/IPv4/TCP frame whose first 34 bytes are the inner frame of
// VXLAN-WIRE-FORMAT.md §9 with IPv4 total length ipLen, sent from TCP port sport to dport.
// The IPv4 checksum stays 0 as in the document; cpworker does not check it.
func wireFrame(ipLen int, sport, dport uint16) []byte {
	f := unhex("aabbccddeeff 112233445566 0800 4500 0054 1234 4000 4006 0000 0a000001 0a000002")
	binary.BigEndian.PutUint16(f[16:], uint16(ipLen))
	tcp := make([]byte, ipLen-20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12] = 0x50 // data offset 5
	tcp[13] = 0x18 // PSH, ACK
	for i := 20; i < len(tcp); i++ {
		tcp[i] = byte(i)
	}
	return append(f, tcp...)
}

// withVLAN inserts an 802.1Q tag after the MAC addresses of f.
func withVLAN(f []byte, vid uint16) []byte {
	return cat(f[:12], []byte{0x81, 0x00, byte(vid >> 8), byte(vid)}, f[12:])
}

// writeWirePcap writes a little-endian microsecond pcap file. It writes the record headers
// itself so that a timestamp such as §10's tv_usec 0x55667788 reaches cpworker unchanged.
func writeWirePcap(t *testing.T, path string, pkts []wirePacket) {
	t.Helper()
	buf := make([]byte, pcapGlobalHeaderLen)
	binary.LittleEndian.PutUint32(buf[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(buf[4:], 2)
	binary.LittleEndian.PutUint16(buf[6:], 4)
	binary.LittleEndian.PutUint32(buf[16:], 65535)
	binary.LittleEndian.PutUint32(buf[20:], uint32(layers.LinkTypeEthernet))
	for _, p := range pkts {
		buf = binary.LittleEndian.AppendUint32(buf, p.sec)
		buf = binary.LittleEndian.AppendUint32(buf, p.usec)
		buf = binary.LittleEndian.AppendUint32(buf, uint32(len(p.data)))
		buf = binary.LittleEndian.AppendUint32(buf, uint32(p.origLen))
		buf = append(buf, p.data...)
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// runWireTasks runs cpworker over tasks until every task has read its file, then stops it.
func runWireTasks(t *testing.T, out string, tasks []wireTask) {
	t.Helper()
	var cfgTasks []map[string]any
	for i, task := range tasks {
		input := filepath.Join(out, fmt.Sprintf("input%d.pcap", i))
		writeWirePcap(t, input, task.input)
		ct := map[string]any{
			"capturer": map[string]any{"type": "pcap_file", "pcap_file": map[string]any{"file_name": input}},
			"outputs":  []map[string]any{task.output},
		}
		if task.reqPattern {
			ct["req_pattern"] = map[string]any{"type": "custom", "custom": map[string]any{"pattern": wireReqPattern}}
		}
		cfgTasks = append(cfgTasks, ct)
	}
	cfg, err := json.MarshalIndent(map[string]any{"tasks": cfgTasks}, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	conf := filepath.Join(out, "config.json")
	if err := os.WriteFile(conf, cfg, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	runner, logp, _ := startReloadWorker(t, out, conf)
	deadline := time.Now().Add(10 * time.Second)
	for strings.Count(readLog(logp), pcapFileEOFLog) < len(tasks) {
		if time.Now().After(deadline) {
			t.Fatalf("not every task finished reading its file; log:\n%s", readLog(logp))
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	if err := runner.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}
	if !runner.WaitExit(5 * time.Second) {
		t.Fatalf("worker did not exit; log:\n%s", readLog(logp))
	}
}

// assertSameDatagrams fails unless got and want hold the same byte strings, in any order.
func assertSameDatagrams(t *testing.T, got, want [][]byte) {
	t.Helper()
	count := map[string]int{}
	for _, w := range want {
		count[hex.EncodeToString(w)]++
	}
	for _, g := range got {
		count[hex.EncodeToString(g)]--
	}
	for h, n := range count {
		switch {
		case n > 0:
			t.Errorf("missing %d datagram(s): %s", n, h)
		case n < 0:
			t.Errorf("unexpected %d datagram(s): %s", -n, h)
		}
	}
}

// ipPayloads returns the IPv4 payload of every captured packet with IP protocol proto.
func ipPayloads(captured [][]byte, proto layers.IPProtocol) [][]byte {
	var out [][]byte
	for _, pkt := range captured {
		p := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
		ip, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ok && ip.Protocol == proto {
			out = append(out, ip.Payload)
		}
	}
	return out
}

// udpPayloads returns the payload of every captured UDP datagram to port.
func udpPayloads(captured [][]byte, port int) [][]byte {
	var out [][]byte
	for _, pkt := range captured {
		p := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
		udp, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if ok && int(udp.DstPort) == port {
			out = append(out, udp.Payload)
		}
	}
	return out
}

// readZMQMessages returns the messages zmq_receiver saved, each stored as a big-endian
// uint32 length followed by the message.
func readZMQMessages(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var msgs [][]byte
	for len(raw) > 0 {
		if len(raw) < 4 || len(raw) < 4+int(binary.BigEndian.Uint32(raw)) {
			t.Fatalf("truncated message in %s", path)
		}
		n := int(binary.BigEndian.Uint32(raw))
		msgs = append(msgs, raw[4:4+n])
		raw = raw[4+n:]
	}
	return msgs
}

// zmqRecord builds the record ZMQ-WIRE-FORMAT.md §4–§6 specify for p: pkt_data_len, the
// packet header, then the frame with the EtherType at l2Len-2 set to 0x8847 and the 4-byte
// tag inserted before the L3 bytes.
func zmqRecord(p wirePacket, l2Len int, tag []byte) []byte {
	frame := cat(p.data[:l2Len-2], unhex("8847"), tag, p.data[l2Len:])
	return cat(be16(len(frame)), be32(p.sec), be32(p.usec), be32(uint32(len(frame))), be32(uint32(p.origLen+4)), frame)
}

// TestWireFormat checks the bytes the gre, vxlan and zmq outputs send against RFC 2784/2890,
// docs/VXLAN-WIRE-FORMAT.md and docs/ZMQ-WIRE-FORMAT.md (issue #243). The expected bytes
// come from those documents, not from the code under test.
//
//   - gre:         GRE header and key for configured service tags; inner frame unchanged
//   - vxlan:       VXLAN header for every row of VXLAN-WIRE-FORMAT.md §9; capture-time trailer
//   - zmq:         batch header, records, packet headers and frames (§3–§6), incl. VLAN and caplen < len
//   - zmq_example: the single-packet message of ZMQ-WIRE-FORMAT.md §10, byte for byte
func TestWireFormat(t *testing.T) {
	if os.Getenv("CPWORKER_BIN") == "" {
		t.Skip("CPWORKER_BIN not set")
	}

	req := wirePacket{data: wireFrame(0x54, 12345, 80), sec: wireTsSec, usec: 123456}
	rsp := wirePacket{data: wireFrame(0x54, 80, 12345), sec: wireTsSec, usec: 250000}
	req.origLen, rsp.origLen = len(req.data), len(rsp.data)

	t.Run("gre", func(t *testing.T) {
		out := setupTestOutputDir(t, "wire_format_gre")
		capPath := filepath.Join(out, "gre_capture.pcap")
		capturer, err := helpers.NewGRECapturer("lo", capPath)
		if err != nil {
			t.Fatalf("new gre capturer: %v", err)
		}
		if err := capturer.Start(); err != nil {
			t.Fatalf("start gre capturer: %v", err)
		}
		defer capturer.Stop()
		time.Sleep(500 * time.Millisecond)

		gre := func(serviceTag int) map[string]any {
			return map[string]any{"type": "gre", "gre": map[string]any{"host": "127.0.0.1", "service_tag": serviceTag}}
		}
		runWireTasks(t, out, []wireTask{
			{input: []wirePacket{req, rsp}, output: gre(0x111)},
			{input: []wirePacket{req, rsp}, reqPattern: true, output: gre(0x123)},
		})
		capturer.Stop()

		// Flags 0x2000: only the key bit (RFC 2890), version 0. Protocol type 0x6558:
		// transparent Ethernet bridging. The key carries the direction in its high 4 bits
		// (USAGE-CPWORKER.md, output.gre). The key without a configured service_tag is #296's.
		want := [][]byte{
			cat(unhex("2000 6558 0000 0111"), req.data),
			cat(unhex("2000 6558 0000 0111"), rsp.data),
			cat(unhex("2000 6558 1000 0123"), req.data),
			cat(unhex("2000 6558 2000 0123"), rsp.data),
		}
		assertSameDatagrams(t, ipPayloads(readPcapData(t, capPath), layers.IPProtocolGRE), want)
	})

	t.Run("vxlan", func(t *testing.T) {
		out := setupTestOutputDir(t, "wire_format_vxlan")
		capPath := filepath.Join(out, "vxlan_capture.pcap")
		capturer, err := helpers.NewVXLANCapturer("lo", wireVXLANPort, capPath)
		if err != nil {
			t.Fatalf("new vxlan capturer: %v", err)
		}
		if err := capturer.Start(); err != nil {
			t.Fatalf("start vxlan capturer: %v", err)
		}
		defer capturer.Stop()
		time.Sleep(500 * time.Millisecond)

		vxlan := func(fields map[string]any) map[string]any {
			cfg := map[string]any{"host": "127.0.0.1", "port": wireVXLANPort}
			for k, v := range fields {
				cfg[k] = v
			}
			return map[string]any{"type": "vxlan", "vxlan": cfg}
		}
		runWireTasks(t, out, []wireTask{
			{input: []wirePacket{req}, output: vxlan(map[string]any{"vni1": 0x1A2})},
			{input: []wirePacket{req, rsp}, reqPattern: true, output: vxlan(map[string]any{"vni1": 0x1A2})},
			{input: []wirePacket{req}, reqPattern: true, output: vxlan(map[string]any{"vni1": 0xFFFFFF})},
			{input: []wirePacket{req}, reqPattern: true, output: vxlan(map[string]any{"vni1": 0x123456})},
			{input: []wirePacket{req}, output: vxlan(map[string]any{"vni2": 0xDF024})},
			{input: []wirePacket{req, rsp}, reqPattern: true, output: vxlan(map[string]any{"vni2": 0xDF024})},
			{input: []wirePacket{req}, output: vxlan(map[string]any{"vni1": 0x1A2, "capture_time": true})},
		})
		capturer.Stop()

		// The headers are the rows of VXLAN-WIRE-FORMAT.md §9, whose inner frame is the
		// first 34 bytes of req and rsp. The capture-time trailer is §6.
		want := [][]byte{
			cat(unhex("08000000 0001A2F5"), req.data),
			cat(unhex("08000000 1001A205"), req.data),
			cat(unhex("08000000 2001A215"), rsp.data),
			cat(unhex("08000000 100FFF62"), req.data),
			cat(unhex("08000000 100456B9"), req.data),
			cat(unhex("08000000 000DF024"), req.data),
			cat(unhex("08000000 000DF025"), req.data),
			cat(unhex("08000000 000DF026"), rsp.data),
			cat(unhex("08000000 0001A2F5"), req.data, be32(req.sec), be32(req.usec*1000)),
		}
		assertSameDatagrams(t, udpPayloads(readPcapData(t, capPath), wireVXLANPort), want)
	})

	t.Run("zmq", func(t *testing.T) {
		out := setupTestOutputDir(t, "wire_format_zmq")
		rawPath := filepath.Join(out, "zmq_raw.dat")
		capturer, err := helpers.NewZMQCapturer(fmt.Sprintf("tcp://127.0.0.1:%d", wireZMQPort), rawPath,
			filepath.Join(out, "zmq_packets.pcap"), filepath.Join(out, "zmq_stats.json"), "helpers/zmq_receiver")
		if err != nil {
			t.Fatalf("new zmq capturer: %v", err)
		}
		if err := capturer.Start(); err != nil {
			t.Fatalf("start zmq capturer: %v", err)
		}
		defer capturer.Stop()

		vlanReq := wirePacket{data: withVLAN(req.data, 100), sec: wireTsSec, usec: 500000}
		vlanReq.origLen = len(vlanReq.data)
		cutReq := wirePacket{data: req.data[:60], sec: wireTsSec, usec: 750000, origLen: len(req.data)}
		runWireTasks(t, out, []wireTask{{
			input:      []wirePacket{req, rsp, vlanReq, cutReq},
			reqPattern: true,
			output: map[string]any{"type": "zmq", "zmq": map[string]any{"host": "127.0.0.1", "port": wireZMQPort,
				"service_tag": 0x1A2, "uuid": "796d506a-46a1-4f4e-bd9a-6075a49ac9f8"}},
		}})
		time.Sleep(time.Second)
		capturer.Stop()

		// §5.1 tags for service_tag 0x1A2; §4.1/§6: caplen counts the tag, len is the
		// original wire length plus the tag.
		want := [][]byte{
			zmqRecord(req, 14, unhex("881A21FF")),
			zmqRecord(rsp, 14, unhex("901A21FF")),
			zmqRecord(vlanReq, 18, unhex("881A21FF")),
			zmqRecord(cutReq, 14, unhex("881A21FF")),
		}
		var got [][]byte
		for i, msg := range readZMQMessages(t, rawPath) {
			if len(msg) < 24 {
				t.Fatalf("message %d is %d bytes, shorter than the batch header", i, len(msg))
			}
			// §3: version 2, pkts_num, keybit = service_tag, uuid without dashes
			if !bytes.Equal(msg[0:2], unhex("0002")) || !bytes.Equal(msg[4:8], unhex("000001A2")) ||
				!bytes.Equal(msg[8:24], unhex("796d506a46a14f4ebd9a6075a49ac9f8")) {
				t.Errorf("message %d batch header: %x", i, msg[:24])
			}
			// §9: the records fill the message exactly
			off := 24
			for n := 0; n < int(binary.BigEndian.Uint16(msg[2:4])); n++ {
				if off+18 > len(msg) || off+18+int(binary.BigEndian.Uint16(msg[off:])) > len(msg) {
					t.Fatalf("message %d: record %d runs past the end", i, n)
				}
				end := off + 18 + int(binary.BigEndian.Uint16(msg[off:]))
				got = append(got, msg[off:end])
				off = end
			}
			if off != len(msg) {
				t.Errorf("message %d: %d bytes after pkts_num records", i, len(msg)-off)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("got %d records, want %d", len(got), len(want))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Errorf("record %d:\n got  %x\n want %x", i, got[i], want[i])
			}
		}
	})

	t.Run("zmq_example", func(t *testing.T) {
		out := setupTestOutputDir(t, "wire_format_zmq_example")
		rawPath := filepath.Join(out, "zmq_raw.dat")
		capturer, err := helpers.NewZMQCapturer(fmt.Sprintf("tcp://127.0.0.1:%d", wireZMQExamplePort), rawPath,
			filepath.Join(out, "zmq_packets.pcap"), filepath.Join(out, "zmq_stats.json"), "helpers/zmq_receiver")
		if err != nil {
			t.Fatalf("new zmq capturer: %v", err)
		}
		if err := capturer.Start(); err != nil {
			t.Fatalf("start zmq capturer: %v", err)
		}
		defer capturer.Stop()

		// §10: one 96-byte packet, service_tag 0, no uuid, INCOMING
		p := wirePacket{data: wireFrame(82, 12345, 80), sec: 0x11223344, usec: 0x55667788, origLen: 96}
		runWireTasks(t, out, []wireTask{{
			input:      []wirePacket{p},
			reqPattern: true,
			output: map[string]any{"type": "zmq", "zmq": map[string]any{"host": "127.0.0.1",
				"port": wireZMQExamplePort, "service_tag": 0}},
		}})
		time.Sleep(time.Second)
		capturer.Stop()

		want := cat(unhex("0002 0001 00000000 0000000000000000 0000000000000000"+
			"0064 11223344 55667788 00000064 00000064 aabbccddeeff 112233445566 8847 880001FF"), p.data[14:])
		msgs := readZMQMessages(t, rawPath)
		if len(msgs) != 1 || !bytes.Equal(msgs[0], want) {
			t.Fatalf("got %d message(s), want the 142-byte message of §10\n got  %x\n want %x", len(msgs), msgs, want)
		}
	})
}
