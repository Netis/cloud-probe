package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Netis/cloud-probe/cpgolib/cpworker"
)

func TestComputePingSummary_Empty(t *testing.T) {
	s := computePingSummary(0, nil)
	if s.Sent != 0 || s.Received != 0 || s.HasSamples {
		t.Fatalf("unexpected: %+v", s)
	}
}

func TestComputePingSummary_AllLost(t *testing.T) {
	s := computePingSummary(3, nil)
	if s.Sent != 3 || s.Received != 0 {
		t.Fatalf("counts wrong: %+v", s)
	}
	if s.LossPct != 100.0 {
		t.Fatalf("loss should be 100, got %v", s.LossPct)
	}
	if s.HasSamples {
		t.Fatal("should not have samples")
	}
}

func TestComputePingSummary_SingleSample(t *testing.T) {
	s := computePingSummary(1, []float64{0.5})
	if !s.HasSamples {
		t.Fatal("expected HasSamples")
	}
	if s.MinMs != 0.5 || s.MaxMs != 0.5 || s.AvgMs != 0.5 {
		t.Fatalf("min/max/avg wrong: %+v", s)
	}
	if s.StddevMs != 0 {
		t.Fatal("stddev should be 0 for single sample")
	}
}

func TestComputePingSummary_MultiSample(t *testing.T) {
	// 1, 2, 3, 4 -> mean=2.5, variance=(2.25+0.25+0.25+2.25)/4=1.25, stddev~=1.118
	s := computePingSummary(5, []float64{1, 2, 3, 4})
	if s.Sent != 5 || s.Received != 4 {
		t.Fatalf("counts wrong: %+v", s)
	}
	if s.LossPct < 19.99 || s.LossPct > 20.01 {
		t.Fatalf("loss should be 20, got %v", s.LossPct)
	}
	if s.MinMs != 1 || s.MaxMs != 4 {
		t.Fatalf("min/max wrong: %+v", s)
	}
	if s.AvgMs != 2.5 {
		t.Fatalf("avg wrong: %v", s.AvgMs)
	}
	if s.StddevMs < 1.117 || s.StddevMs > 1.119 {
		t.Fatalf("stddev wrong: %v", s.StddevMs)
	}
}

// fakePingClient records calls and returns canned RTTs.
type fakePingClient struct {
	rtts []time.Duration
	idx  int
	fail error
}

func (f *fakePingClient) Close() error                                                       { return nil }
func (f *fakePingClient) Dial(context.Context) error                                         { return nil }
func (f *fakePingClient) CollectStatsSummary(context.Context) (cpworker.StatsSummary, error) { return cpworker.StatsSummary{}, nil }
func (f *fakePingClient) Info(context.Context) (cpworker.InfoSummary, error)                 { return cpworker.InfoSummary{}, nil }
func (f *fakePingClient) Ping(context.Context) (cpworker.PingResult, error) {
	if f.fail != nil {
		return cpworker.PingResult{}, f.fail
	}
	if f.idx >= len(f.rtts) {
		return cpworker.PingResult{}, errors.New("no more samples")
	}
	r := cpworker.PingResult{Rtt: f.rtts[f.idx], When: time.Unix(0, int64(f.idx)*int64(time.Millisecond))}
	f.idx++
	return r, nil
}

func TestRunPing_TextCount(t *testing.T) {
	client := &fakePingClient{rtts: []time.Duration{500 * time.Microsecond, 1500 * time.Microsecond}}
	var buf bytes.Buffer
	err := runPing(context.Background(), client, &buf, 2, time.Microsecond, false, FormatText, "/tmp/sock")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"PING cpworker", "seq=0", "seq=1", "ping statistics", "2 transmitted, 2 received"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestRunPing_JSONLCount(t *testing.T) {
	client := &fakePingClient{rtts: []time.Duration{500 * time.Microsecond, 1500 * time.Microsecond}}
	var buf bytes.Buffer
	err := runPing(context.Background(), client, &buf, 2, time.Microsecond, false, FormatJSONL, "/tmp/sock")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 jsonl lines (2 samples + 1 summary), got %d:\n%s", len(lines), buf.String())
	}
	var s1 pingSampleRecord
	if err := json.Unmarshal([]byte(lines[0]), &s1); err != nil {
		t.Fatalf("decode line 0: %v", err)
	}
	if s1.Kind != "sample" || s1.Seq != 0 {
		t.Fatalf("bad sample: %+v", s1)
	}
	var summ pingSummaryRecord
	if err := json.Unmarshal([]byte(lines[2]), &summ); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if summ.Kind != "summary" || summ.Sent != 2 || summ.Received != 2 || summ.LossPct != 0 {
		t.Fatalf("bad summary: %+v", summ)
	}
}

func TestRunPing_Quiet(t *testing.T) {
	client := &fakePingClient{rtts: []time.Duration{500 * time.Microsecond, 1500 * time.Microsecond}}
	var buf bytes.Buffer
	err := runPing(context.Background(), client, &buf, 2, time.Microsecond, true, FormatText, "/tmp/sock")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "seq=0") || strings.Contains(out, "seq=1") {
		t.Errorf("quiet mode should not emit per-ping lines:\n%s", out)
	}
	if !strings.Contains(out, "ping statistics") {
		t.Errorf("quiet mode should still emit summary:\n%s", out)
	}
}

func TestRunPing_ContextCancelled(t *testing.T) {
	client := &fakePingClient{rtts: []time.Duration{1 * time.Microsecond, 1 * time.Microsecond, 1 * time.Microsecond}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	var buf bytes.Buffer
	err := runPing(ctx, client, &buf, 0, time.Microsecond, false, FormatText, "/tmp/sock")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "ping statistics") {
		t.Errorf("expected summary on context cancel:\n%s", buf.String())
	}
}
