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

func (f *fakeStatsClient) Close() error                                            { return nil }
func (f *fakeStatsClient) Dial(context.Context) error                              { return nil }
func (f *fakeStatsClient) Ping(context.Context) (cpworker.PingResult, error)       { return cpworker.PingResult{}, nil }
func (f *fakeStatsClient) Info(context.Context) (cpworker.InfoSummary, error)      { return cpworker.InfoSummary{}, nil }
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
	if rec.Sample != "raw" {
		t.Errorf("sample type should be 'raw' at -n=1, got %q", rec.Sample)
	}
	if rec.Rates != nil {
		t.Errorf("rates should be omitted in raw mode, got %+v", rec.Rates)
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
	if rec.Sample != "rate" {
		t.Errorf("sample type should be 'rate' at -n>=2, got %q", rec.Sample)
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
