package integration

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket/pcap"
)

const (
	pcapGlobalHeaderLen = 24
	pcapRecordHeaderLen = 16

	pcapFileEOFLog       = "end of file"
	pcapFileReadErrorLog = "read pcap file error"
)

// pcapRecord is one record of a little-endian classic pcap file: its offset in
// the file and its captured bytes.
type pcapRecord struct {
	offset int
	data   []byte
}

// splitPcapRecords parses a little-endian classic pcap file into its records.
func splitPcapRecords(t *testing.T, raw []byte) []pcapRecord {
	t.Helper()
	if len(raw) < pcapGlobalHeaderLen || binary.LittleEndian.Uint32(raw) != 0xa1b2c3d4 {
		t.Fatalf("not a little-endian microsecond pcap file")
	}
	var recs []pcapRecord
	for off := pcapGlobalHeaderLen; off < len(raw); {
		if off+pcapRecordHeaderLen > len(raw) {
			t.Fatalf("truncated record header at offset %d", off)
		}
		inclLen := int(binary.LittleEndian.Uint32(raw[off+8:]))
		end := off + pcapRecordHeaderLen + inclLen
		if end > len(raw) {
			t.Fatalf("truncated record data at offset %d", off)
		}
		recs = append(recs, pcapRecord{offset: off, data: raw[off+pcapRecordHeaderLen : end]})
		off = end
	}
	return recs
}

// readPcapData returns the captured bytes of every packet in the pcap file.
func readPcapData(t *testing.T, path string) [][]byte {
	t.Helper()
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		t.Fatalf("open pcap %s: %v", path, err)
	}
	defer handle.Close()
	var out [][]byte
	for {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			return out
		}
		out = append(out, append([]byte(nil), data...))
	}
}

// waitForAnyLog polls the log file until it contains one of substrs or the
// deadline passes.
func waitForAnyLog(path string, substrs []string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		data, _ := os.ReadFile(path)
		for _, s := range substrs {
			if strings.Contains(string(data), s) {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestPcapFileCorrupt checks that a pcap_file capturer reports a libpcap read
// error instead of "end of file", forwards the records before the damage, and
// stops reading the file there (issue #246). Reading on after an error could
// parse packet data as record headers and forward garbage.
//
//   - intact:             control; every record forwarded, "end of file" logged
//   - truncated_record:   record #9's data is cut short at the end of the file
//   - oversized_incl_len: record #9's incl_len is 0x7ffffff0, the rest of the file intact
func TestPcapFileCorrupt(t *testing.T) {
	if os.Getenv("CPWORKER_BIN") == "" {
		t.Skip("CPWORKER_BIN not set")
	}

	raw, err := os.ReadFile(filepath.Join(getTestDataDir(), "pcaps", "http.pcap"))
	if err != nil {
		t.Fatalf("read http.pcap: %v", err)
	}
	recs := splitPcapRecords(t, raw)
	const damaged = 9 // index of the damaged record; records 0..8 stay intact
	if len(recs) <= damaged+1 {
		t.Fatalf("http.pcap has %d records, need more than %d", len(recs), damaged+1)
	}
	bad := recs[damaged]

	cases := []struct {
		name        string
		file        func() []byte
		wantRecords int
		wantError   bool
	}{
		{"intact", func() []byte { return raw }, len(recs), false},
		{"truncated_record", func() []byte {
			return raw[:bad.offset+pcapRecordHeaderLen+len(bad.data)/2]
		}, damaged, true},
		{"oversized_incl_len", func() []byte {
			b := append([]byte(nil), raw...)
			binary.LittleEndian.PutUint32(b[bad.offset+8:], 0x7ffffff0)
			return b
		}, damaged, true},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			out := setupTestOutputDir(t, "pcap_file_corrupt/"+c.name)
			input := filepath.Join(out, "input.pcap")
			if err := os.WriteFile(input, c.file(), 0o644); err != nil {
				t.Fatalf("write input: %v", err)
			}
			output := filepath.Join(out, "output.pcap")
			cfg, err := json.MarshalIndent(map[string]any{
				"tasks": []map[string]any{{
					"capturer": map[string]any{"type": "pcap_file", "pcap_file": map[string]any{"file_name": input}},
					"outputs":  []map[string]any{{"type": "file", "file": map[string]any{"name": output}}},
				}},
			}, "", "  ")
			if err != nil {
				t.Fatalf("marshal config: %v", err)
			}
			conf := filepath.Join(out, "config.json")
			if err := os.WriteFile(conf, cfg, 0o644); err != nil {
				t.Fatalf("write config: %v", err)
			}

			runner, logp, _ := startReloadWorker(t, out, conf)
			if !waitForAnyLog(logp, []string{pcapFileEOFLog, pcapFileReadErrorLog}, 5*time.Second) {
				t.Fatalf("worker never finished reading the file; log:\n%s", readLog(logp))
			}
			time.Sleep(500 * time.Millisecond) // let a worker that reads on after the error show it
			if err := runner.Signal(syscall.SIGINT); err != nil {
				t.Fatalf("send SIGINT: %v", err)
			}
			if !runner.WaitExit(5 * time.Second) {
				t.Fatalf("worker did not exit; log:\n%s", readLog(logp))
			}

			log := readLog(logp)
			if c.wantError {
				if !strings.Contains(log, pcapFileReadErrorLog) {
					t.Errorf("no %q line for a damaged file; log:\n%s", pcapFileReadErrorLog, log)
				}
				if strings.Contains(log, pcapFileEOFLog) {
					t.Errorf("damaged file reported as %q; log:\n%s", pcapFileEOFLog, log)
				}
			} else {
				if strings.Contains(log, pcapFileReadErrorLog) {
					t.Errorf("unexpected %q line for an intact file; log:\n%s", pcapFileReadErrorLog, log)
				}
				if !strings.Contains(log, pcapFileEOFLog) {
					t.Errorf("no %q line for an intact file; log:\n%s", pcapFileEOFLog, log)
				}
			}

			got := readPcapData(t, output)
			if len(got) != c.wantRecords {
				t.Errorf("forwarded %d packets, want %d", len(got), c.wantRecords)
			}
			for i := 0; i < len(got) && i < c.wantRecords; i++ {
				if !bytes.Equal(got[i], recs[i].data) {
					t.Errorf("packet %d differs from input record %d", i, i)
				}
			}
		})
	}
}
