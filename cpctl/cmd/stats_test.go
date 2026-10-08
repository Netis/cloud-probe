package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Netis/cloud-probe/cpgolib/cpworker"
)

// fakeStatsClient returns a sequence of canned StatsSummary snapshots.
type fakeStatsClient struct {
	snapshots []cpworker.StatsSummary
	idx       int
}

func (f *fakeStatsClient) Close() error               { return nil }
func (f *fakeStatsClient) Dial(context.Context) error { return nil }
func (f *fakeStatsClient) Ping(context.Context) (cpworker.PingResult, error) {
	return cpworker.PingResult{}, nil
}

func (f *fakeStatsClient) Info(context.Context) (cpworker.InfoSummary, error) {
	return cpworker.InfoSummary{}, nil
}
func (f *fakeStatsClient) ReloadConfig(context.Context) error { return nil }
func (f *fakeStatsClient) CollectStatsSummary(context.Context) (cpworker.StatsSummary, error) {
	if f.idx >= len(f.snapshots) {
		return f.snapshots[len(f.snapshots)-1], nil
	}
	s := f.snapshots[f.idx]
	f.idx++
	return s, nil
}

func makeStats(tSec int64, capBytes, fwdBytes, capPkts, fwdPkts uint64) cpworker.StatsSummary {
	var s cpworker.StatsSummary
	s.Time.Sec = tSec
	s.Capture.CapBytes = cpworker.BytesStats{Bytes: capBytes}
	s.Capture.CapPackets = cpworker.PacketsStats{Packets: capPkts}
	s.Output.FwdBytes = cpworker.BytesStats{Bytes: fwdBytes}
	s.Output.FwdPackets = cpworker.PacketsStats{Packets: fwdPkts}
	return s
}

func TestRunStats_RawN1Text(t *testing.T) {
	client := &fakeStatsClient{snapshots: []cpworker.StatsSummary{
		makeStats(1000, 4096, 2048, 10, 5),
	}}
	var buf bytes.Buffer
	if err := runStats(context.Background(), client, &buf, 1, time.Microsecond, FormatText); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Cap Bytes") || !strings.Contains(out, "4.0 KB") {
		t.Errorf("expected raw bytes formatted in text:\n%s", out)
	}
	// raw mode must NOT emit the per-tick separator that diff mode prints
	if strings.Contains(out, "; (") {
		t.Errorf("raw mode should not print per-second rates:\n%s", out)
	}
}

func TestRunStats_RawN1JSONL(t *testing.T) {
	client := &fakeStatsClient{snapshots: []cpworker.StatsSummary{
		makeStats(1000, 4096, 2048, 10, 5),
	}}
	var buf bytes.Buffer
	if err := runStats(context.Background(), client, &buf, 1, time.Microsecond, FormatJSONL); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 jsonl line for -n=1, got %d:\n%s", len(lines), buf.String())
	}
	var rec statsRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Kind != "raw" {
		t.Errorf("kind should be 'raw' at -n=1, got %q", rec.Kind)
	}
	if rec.Rates != nil {
		t.Errorf("rates should be null in raw mode, got %+v", rec.Rates)
	}
	if rec.Counters["cap_bytes"] == nil {
		t.Errorf("counters.cap_bytes missing")
	}
}

func TestRunStats_DiffN2Text(t *testing.T) {
	client := &fakeStatsClient{snapshots: []cpworker.StatsSummary{
		makeStats(1000, 1000, 500, 10, 5),
		makeStats(1002, 3000, 1500, 30, 15), // +2s, +2000B cap, +1000B fwd
	}}
	var buf bytes.Buffer
	if err := runStats(context.Background(), client, &buf, 2, time.Microsecond, FormatText); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "; (") {
		t.Errorf("diff mode should print per-second rates:\n%s", out)
	}
	if !strings.Contains(out, "-------") {
		t.Errorf("diff mode should print separator:\n%s", out)
	}
}

func TestRunStats_DiffN2JSONL(t *testing.T) {
	client := &fakeStatsClient{snapshots: []cpworker.StatsSummary{
		makeStats(1000, 1000, 500, 10, 5),
		makeStats(1002, 3000, 1500, 30, 15),
	}}
	var buf bytes.Buffer
	if err := runStats(context.Background(), client, &buf, 2, time.Microsecond, FormatJSONL); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// -n=2 emits 1 diff record (first sample establishes baseline)
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 jsonl line for -n=2 (1 diff), got %d:\n%s", len(lines), buf.String())
	}
	var rec statsRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Kind != "rate" {
		t.Errorf("kind should be 'rate' at -n>=2, got %q", rec.Kind)
	}
	if rec.IntervalS == nil || *rec.IntervalS != 2.0 {
		t.Errorf("interval should be 2.0, got %v", rec.IntervalS)
	}
	if rec.Rates == nil {
		t.Fatal("rates should be present in diff mode")
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
	}
	for _, c := range cases {
		got := formatBytes(c.in)
		if got != c.want {
			t.Errorf("formatBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPacketsStatsPerSec_ZeroSecs(t *testing.T) {
	in := cpworker.PacketsStats{Packets: 100}
	got := packetsStatsPerSec(in, 0)
	if got != in {
		t.Errorf("zero seconds should return input unchanged, got %+v", got)
	}
}

// #297: ts is the snapshot's wall-clock time, not its CLOCK_MONOTONIC time.
func TestRunStats_TsIsSnapshotWallTime(t *testing.T) {
	withWall := func(s cpworker.StatsSummary, sec int64) cpworker.StatsSummary {
		s.WallTime.Sec = sec
		s.WallTime.Nsec = 250000000
		return s
	}
	cases := []struct {
		name      string
		count     int
		snapshots []cpworker.StatsSummary
		wantTs    string
	}{
		{"raw", 1, []cpworker.StatsSummary{withWall(makeStats(632655, 0, 0, 0, 0), 1759900000)}, "2025-10-08T05:06:40.25Z"},
		{"rate", 2, []cpworker.StatsSummary{
			withWall(makeStats(632655, 0, 0, 0, 0), 1759900000),
			withWall(makeStats(632660, 0, 0, 0, 0), 1759900005),
		}, "2025-10-08T05:06:45.25Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeStatsClient{snapshots: tc.snapshots}
			var buf bytes.Buffer
			if err := runStats(context.Background(), client, &buf, tc.count, time.Microsecond, FormatJSONL); err != nil {
				t.Fatal(err)
			}
			var rec statsRecord
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
				t.Fatalf("decode: %v\n%s", err, buf.String())
			}
			if rec.Ts != tc.wantTs {
				t.Errorf("ts = %q, want %q", rec.Ts, tc.wantTs)
			}
		})
	}
}

// #299: heartbeats are reported in their own counter.
func TestRunStats_ReportsHeartbeatPackets(t *testing.T) {
	s0 := makeStats(1000, 0, 0, 0, 0)
	s1 := makeStats(1005, 0, 0, 0, 0)
	s1.Output.HeartbeatPackets = cpworker.PacketsStats{Packets: 5}

	t.Run("jsonl", func(t *testing.T) {
		client := &fakeStatsClient{snapshots: []cpworker.StatsSummary{s0, s1}}
		var buf bytes.Buffer
		if err := runStats(context.Background(), client, &buf, 2, time.Microsecond, FormatJSONL); err != nil {
			t.Fatal(err)
		}
		var rec statsRecord
		if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
			t.Fatalf("decode: %v", err)
		}
		hb, ok := rec.Counters["heartbeat_packets"].(map[string]any)
		if !ok || hb["packets"] != float64(5) {
			t.Errorf("counters.heartbeat_packets = %v, want packets 5", rec.Counters["heartbeat_packets"])
		}
		rate, ok := rec.Rates["heartbeat_packets_per_sec"].(map[string]any)
		if !ok || rate["packets"] != float64(1) {
			t.Errorf("rates.heartbeat_packets_per_sec = %v, want packets 1", rec.Rates["heartbeat_packets_per_sec"])
		}
	})
	t.Run("text", func(t *testing.T) {
		for _, count := range []int{1, 2} {
			client := &fakeStatsClient{snapshots: []cpworker.StatsSummary{s1, s1}}
			if count == 2 {
				client.snapshots = []cpworker.StatsSummary{s0, s1}
			}
			var buf bytes.Buffer
			if err := runStats(context.Background(), client, &buf, count, time.Microsecond, FormatText); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buf.String(), "Heartbeat Packets") {
				t.Errorf("-n %d text output has no Heartbeat Packets row:\n%s", count, buf.String())
			}
		}
	})
}
