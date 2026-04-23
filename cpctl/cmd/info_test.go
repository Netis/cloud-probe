package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Netis/cloud-probe/cpgolib/cpworker"
)

func sampleInfo() cpworker.InfoSummary {
	return cpworker.InfoSummary{
		Version:        "0.9.x-test",
		Pid:            12345,
		UptimeSec:      3661,
		ConfigPath:     "cpworker.json",
		WorkingDir:     "/etc/cloud-probe",
		LogDestination: "stderr",
		StartedAtSec:   1700000000,
	}
}

func TestEmitInfo_Text(t *testing.T) {
	var buf bytes.Buffer
	if err := emitInfo(&buf, sampleInfo(), FormatText); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"0.9.x-test", "12345", "cpworker.json", "/etc/cloud-probe", "stderr", "1h1m1s"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestEmitInfo_JSONL(t *testing.T) {
	var buf bytes.Buffer
	if err := emitInfo(&buf, sampleInfo(), FormatJSONL); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(buf.String())
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("jsonl output must end with a newline")
	}
	var got cpworker.InfoSummary
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != sampleInfo() {
		t.Errorf("decoded != original:\n got: %+v\nwant: %+v", got, sampleInfo())
	}
}
