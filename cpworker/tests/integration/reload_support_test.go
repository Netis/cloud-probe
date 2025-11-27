package integration

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// waitForLog polls the log file until it contains substr or the deadline passes.
// A false return is the deadlock / no-progress signal.
func waitForLog(t *testing.T, path, substr string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if logContains(path, substr) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return logContains(path, substr)
}

// logContains reports whether the file at path contains substr.
func logContains(path, substr string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), substr)
}

// readLog returns the full contents of path (for failure messages).
func readLog(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

// sendUDP sends each payload as one UDP datagram to addr (e.g. "127.0.0.1:54321").
// It uses an unconnected socket (ListenPacket + WriteTo) on purpose: there is no
// listener on the target port, so a connected socket (net.Dial) would surface the
// kernel's ICMP port-unreachable as ECONNREFUSED on the *next* Write. An unconnected
// socket doesn't get that error attributed to it, and the datagrams still traverse
// `lo` and get captured by cpworker.
func sendUDP(t *testing.T, addr string, payloads []string) {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve udp %s: %v", addr, err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()
	for _, p := range payloads {
		if _, err := conn.WriteTo([]byte(p), raddr); err != nil {
			t.Fatalf("send udp %q: %v", p, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// markers builds n payloads like "PREFIX-00", "PREFIX-01", ...
func markers(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%02d", prefix, i)
	}
	return out
}

// pcapHasPayload reports whether any packet in the pcap file contains marker.
func pcapHasPayload(t *testing.T, path, marker string) bool {
	t.Helper()
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		// Missing/empty pcap -> treat as "no such payload" so the caller's own
		// assertion message (e.g. "a.pcap missing BATCH1") is what surfaces,
		// instead of a confusing fatal "open pcap: no such file".
		t.Logf("open pcap %s: %v", path, err)
		return false
	}
	defer handle.Close()
	want := []byte(marker)
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		if bytes.Contains(pkt.Data(), want) {
			return true
		}
	}
	return false
}
