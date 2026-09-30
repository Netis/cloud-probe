package cmd

// Contract tests for the jsonl output shapes documented in
// docs/REFACTOR-CPCTL.md. Every test decodes raw JSON into map[string]any
// and checks key names and null-ness directly, so a struct round-trip can't
// hide a wrong key name or a dropped field.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Netis/cloud-probe/cpgolib/cpworker"
)

func decodeJSONLines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line is not a JSON object: %q: %v", line, err)
		}
		recs = append(recs, m)
	}
	return recs
}

func assertKeys(t *testing.T, rec map[string]any, want ...string) {
	t.Helper()
	got := make([]string, 0, len(rec))
	for k := range rec {
		got = append(got, k)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("keys mismatch:\n got: %v\nwant: %v\n rec: %v", got, want, rec)
	}
}

func assertRFC3339(t *testing.T, rec map[string]any, key string) {
	t.Helper()
	s, ok := rec[key].(string)
	if !ok {
		t.Fatalf("%s should be a string, got %T (%v)", key, rec[key], rec[key])
	}
	if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
		t.Errorf("%s is not RFC 3339: %q", key, s)
	}
}

// §5.3: errors on stderr are one jsonl line {"level","ts","msg","err"}.
func TestContract_ErrorIsJSONLOnStderr(t *testing.T) {
	var stderr bytes.Buffer
	reportError(newLogger(&stderr, FormatJSONL), errors.New("dial unix /x.sock: connect: no such file"))

	recs := decodeJSONLines(t, stderr.String())
	if len(recs) != 1 {
		t.Fatalf("want 1 stderr line, got %d:\n%s", len(recs), stderr.String())
	}
	rec := recs[0]
	assertKeys(t, rec, "level", "ts", "msg", "err")
	if rec["level"] != "error" {
		t.Errorf("level should be \"error\", got %v", rec["level"])
	}
	assertRFC3339(t, rec, "ts")
	if rec["err"] != "dial unix /x.sock: connect: no such file" {
		t.Errorf("err mismatch: %v", rec["err"])
	}
}

// Non-error logs (e.g. "received signal") must also be JSON in jsonl mode.
func TestContract_InfoLogIsJSONLOnStderr(t *testing.T) {
	var stderr bytes.Buffer
	newLogger(&stderr, FormatJSONL).Info("received signal", slog.String("signal", "interrupt"))

	recs := decodeJSONLines(t, stderr.String())
	if len(recs) != 1 {
		t.Fatalf("want 1 stderr line, got %d:\n%s", len(recs), stderr.String())
	}
	assertKeys(t, recs[0], "level", "ts", "msg", "signal")
	if recs[0]["level"] != "info" {
		t.Errorf("level should be \"info\", got %v", recs[0]["level"])
	}
}

// §5.3/§6.1: a failed ping goes to stderr; stdout carries only data records.
func TestContract_PingErrorGoesToStderr(t *testing.T) {
	for _, quiet := range []bool{false, true} {
		client := &fakePingClient{fail: errors.New("status ERROR")}
		var stdout, stderr bytes.Buffer
		err := runPing(context.Background(), client, &stdout, newLogger(&stderr, FormatJSONL), 1, time.Microsecond,
			quiet, FormatJSONL, "/tmp/sock")
		if err != nil {
			t.Fatal(err)
		}

		out := decodeJSONLines(t, stdout.String())
		if len(out) != 1 || out[0]["kind"] != "summary" {
			t.Errorf("quiet=%v: stdout should hold only the summary, got:\n%s", quiet, stdout.String())
		}

		errs := decodeJSONLines(t, stderr.String())
		if len(errs) != 1 {
			t.Fatalf("quiet=%v: want 1 stderr line, got %d:\n%s", quiet, len(errs), stderr.String())
		}
		assertKeys(t, errs[0], "level", "ts", "msg", "seq", "err")
		if errs[0]["level"] != "error" || errs[0]["seq"] != float64(0) || errs[0]["err"] != "status ERROR" {
			t.Errorf("quiet=%v: bad error record: %v", quiet, errs[0])
		}
	}
}

// §6.1: sample and summary lines carry "kind"; summary has a fixed key set.
func TestContract_PingShapes(t *testing.T) {
	client := &fakePingClient{rtts: []time.Duration{500 * time.Microsecond}}
	var stdout, stderr bytes.Buffer
	err := runPing(context.Background(), client, &stdout, newLogger(&stderr, FormatJSONL), 1, time.Microsecond,
		false, FormatJSONL, "/tmp/sock")
	if err != nil {
		t.Fatal(err)
	}
	recs := decodeJSONLines(t, stdout.String())
	if len(recs) != 2 {
		t.Fatalf("want sample + summary, got %d:\n%s", len(recs), stdout.String())
	}

	assertKeys(t, recs[0], "kind", "ts", "seq", "rtt_ms")
	if recs[0]["kind"] != "sample" {
		t.Errorf("first line kind should be sample: %v", recs[0])
	}
	assertRFC3339(t, recs[0], "ts")

	sum := recs[1]
	assertKeys(t, sum, "kind", "sent", "received", "loss_pct", "min_ms", "avg_ms", "max_ms", "stddev_ms")
	if sum["kind"] != "summary" {
		t.Errorf("last line kind should be summary: %v", sum)
	}
	// A single sample has stddev 0; it must still be present, not dropped.
	if sum["stddev_ms"] != float64(0) {
		t.Errorf("stddev_ms should be 0 for one sample, got %v", sum["stddev_ms"])
	}
}

// §6.1: with no replies the RTT fields are null, not missing.
func TestContract_PingSummaryNoReplies(t *testing.T) {
	client := &fakePingClient{fail: errors.New("status ERROR")}
	var stdout, stderr bytes.Buffer
	err := runPing(context.Background(), client, &stdout, newLogger(&stderr, FormatJSONL), 2, time.Microsecond,
		true, FormatJSONL, "/tmp/sock")
	if err != nil {
		t.Fatal(err)
	}
	recs := decodeJSONLines(t, stdout.String())
	if len(recs) != 1 {
		t.Fatalf("want 1 summary line, got %d:\n%s", len(recs), stdout.String())
	}
	sum := recs[0]
	assertKeys(t, sum, "kind", "sent", "received", "loss_pct", "min_ms", "avg_ms", "max_ms", "stddev_ms")
	for _, k := range []string{"min_ms", "avg_ms", "max_ms", "stddev_ms"} {
		if sum[k] != nil {
			t.Errorf("%s should be null with no replies, got %v", k, sum[k])
		}
	}
	if sum["sent"] != float64(2) || sum["received"] != float64(0) || sum["loss_pct"] != float64(100) {
		t.Errorf("bad counts: %v", sum)
	}
}

// §6.2: -n 1 emits kind "raw" with interval_sec and rates present as null.
func TestContract_StatsRawShape(t *testing.T) {
	client := &fakeStatsClient{snapshots: []cpworker.StatsSummary{makeStats(1000, 4096, 2048, 10, 5)}}
	var stdout bytes.Buffer
	if err := runStats(context.Background(), client, &stdout, 1, time.Microsecond, FormatJSONL); err != nil {
		t.Fatal(err)
	}
	recs := decodeJSONLines(t, stdout.String())
	if len(recs) != 1 {
		t.Fatalf("want 1 line, got %d:\n%s", len(recs), stdout.String())
	}
	rec := recs[0]
	assertKeys(t, rec, "kind", "ts", "interval_sec", "counters", "rates")
	if rec["kind"] != "raw" {
		t.Errorf("kind should be raw, got %v", rec["kind"])
	}
	if rec["interval_sec"] != nil || rec["rates"] != nil {
		t.Errorf("interval_sec and rates should be null for a raw sample: %v", rec)
	}
	assertRFC3339(t, rec, "ts")
}

// §6.2: -n >= 2 emits kind "rate" with the same key set, all populated.
func TestContract_StatsRateShape(t *testing.T) {
	client := &fakeStatsClient{snapshots: []cpworker.StatsSummary{
		makeStats(1000, 1000, 500, 10, 5),
		makeStats(1002, 3000, 1500, 30, 15),
	}}
	var stdout bytes.Buffer
	if err := runStats(context.Background(), client, &stdout, 2, time.Microsecond, FormatJSONL); err != nil {
		t.Fatal(err)
	}
	recs := decodeJSONLines(t, stdout.String())
	if len(recs) != 1 {
		t.Fatalf("want 1 line, got %d:\n%s", len(recs), stdout.String())
	}
	rec := recs[0]
	assertKeys(t, rec, "kind", "ts", "interval_sec", "counters", "rates")
	if rec["kind"] != "rate" || rec["interval_sec"] != float64(2) {
		t.Errorf("bad rate record: %v", rec)
	}
	rates, ok := rec["rates"].(map[string]any)
	if !ok || rates["cap_bytes_per_sec"] == nil {
		t.Errorf("rates.cap_bytes_per_sec missing: %v", rec["rates"])
	}
}

// §6.3: info uses snake_case keys and an RFC 3339 started_at.
func TestContract_InfoShape(t *testing.T) {
	var stdout bytes.Buffer
	if err := emitInfo(&stdout, sampleInfo(), FormatJSONL); err != nil {
		t.Fatal(err)
	}
	recs := decodeJSONLines(t, stdout.String())
	if len(recs) != 1 {
		t.Fatalf("want 1 line, got %d:\n%s", len(recs), stdout.String())
	}
	rec := recs[0]
	assertKeys(t, rec, "version", "pid", "uptime_sec", "config_path", "working_dir", "log_destination", "started_at")
	if rec["started_at"] != "2023-11-14T22:13:20Z" {
		t.Errorf("started_at should be RFC 3339 UTC, got %v", rec["started_at"])
	}
	if rec["pid"] != float64(12345) || rec["uptime_sec"] != float64(3661) {
		t.Errorf("bad numeric fields: %v", rec)
	}
}
