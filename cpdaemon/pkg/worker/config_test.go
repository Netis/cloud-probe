package worker

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/common"
)

// These tests pin the *behavioral contract* of fingerprint generation so the
// upcoming reflection-based refactor can be verified for correctness.
//
// They intentionally do NOT assert exact fingerprint/UUID strings: the refactor
// is expected to change the concrete hash values (e.g. label key "output.N." may
// become "outputs.N."). What MUST survive any refactor is the invariant that
// every config field reaches the fingerprint — otherwise reload silently reuses a
// stale task (the bug these tests guard against). If the refactor drops a field,
// the corresponding mutation case below will fail.

// fingerprintOf computes the same fingerprint cpdaemon sends to cpworker for a task.
func fingerprintOf(c *TaskConfig) string {
	return common.LabelsToFingerprint(c.FingerPrintLables()).UUID().String()
}

// ── baseline builders: every optional field populated with a known non-zero value ──

func baseLibpcap() *LibpcapConfig {
	return &LibpcapConfig{
		Interface:            "eth0",
		Snaplen:              lo.ToPtr(65535),
		Netns:                lo.ToPtr("ns1"),
		Bpf:                  lo.ToPtr("tcp port 80"),
		BufferSizeMB:         lo.ToPtr[uint64](256),
		TimeoutMs:            lo.ToPtr(100),
		NotFilterOutputHosts: lo.ToPtr(true),
	}
}

func baseReqPattern() *ReqPatternConfig {
	return &ReqPatternConfig{
		Type:   ReqPatternType_CUSTOM,
		Custom: &CustomReqPatternConfig{Pattern: "host 1.2.3.4"},
	}
}

func taskWith(out OutputConfig) *TaskConfig {
	return &TaskConfig{
		ReqPattern: baseReqPattern(),
		Capturer:   CapturerConfig{Type: CapturerType_Libpcap, Libpcap: baseLibpcap()},
		Outputs:    []OutputConfig{out},
	}
}

func baseVxlanOutput() OutputConfig {
	return OutputConfig{
		Type:          OutputType_Vxlan,
		RateLimitMbps: lo.ToPtr[uint64](100),
		Slice:         lo.ToPtr[uint64](128),
		Vxlan: &VxlanOutputConfig{
			Host:        "10.0.0.1",
			Port:        lo.ToPtr[int32](4789),
			CaptureTime: lo.ToPtr(true),
			Vni1:        lo.ToPtr[uint32](100),
			Vni2:        lo.ToPtr[uint32](200),
			BindDevice:  lo.ToPtr("eth1"),
			Pmtudisc:    lo.ToPtr("do"),
			Split: &PacketSplitConfig{
				MaxPayloadSize:      lo.ToPtr[int32](1400),
				RecalculateChecksum: lo.ToPtr(true),
			},
		},
	}
}

func baseGreOutput() OutputConfig {
	return OutputConfig{
		Type:          OutputType_Gre,
		RateLimitMbps: lo.ToPtr[uint64](100),
		Slice:         lo.ToPtr[uint64](128),
		Gre: &GreOutputConfig{
			Host:       "10.0.0.2",
			ServiceTag: lo.ToPtr[uint32](3456),
			BindDevice: lo.ToPtr("eth1"),
			Pmtudisc:   lo.ToPtr("do"),
		},
	}
}

func baseZmqOutput() OutputConfig {
	return OutputConfig{
		Type:          OutputType_Zmq,
		RateLimitMbps: lo.ToPtr[uint64](100),
		Slice:         lo.ToPtr[uint64](128),
		Zmq: &ZmqOutputConfig{
			Host:        "10.0.0.3",
			Port:        5555,
			Hwm:         lo.ToPtr(2000),
			ServiceTag:  lo.ToPtr[uint32](7),
			Uuid:        "u-1",
			HeartbeatMs: lo.ToPtr[int32](2000),
		},
	}
}

func baseFileOutput() OutputConfig {
	return OutputConfig{
		Type:          OutputType_File,
		RateLimitMbps: lo.ToPtr[uint64](100),
		Slice:         lo.ToPtr[uint64](128),
		File:          &FileOutputConfig{Name: "out.pcap"},
	}
}

func baseRotatingFileOutput() OutputConfig {
	return OutputConfig{
		Type:          OutputType_RotatingFile,
		RateLimitMbps: lo.ToPtr[uint64](100),
		Slice:         lo.ToPtr[uint64](128),
		RotatingFile: &RotatingFileOutputConfig{
			FileRoot:        "/tmp/cap",
			MaxFileInterval: lo.ToPtr[int32](60),
		},
	}
}

// ── mutation runner ──

type mutator struct {
	name   string
	mutate func(*TaskConfig)
}

// runMutations asserts that EACH single-field mutation changes the fingerprint
// (the field is covered) AND that no two distinct mutations collide to the same
// fingerprint (label keys are distinct — catches prefix/key bugs).
func runMutations(t *testing.T, makeBase func() *TaskConfig, muts []mutator) {
	t.Helper()
	base := fingerprintOf(makeBase())
	seen := map[string]string{base: "<baseline>"}
	for _, m := range muts {
		c := makeBase()
		m.mutate(c)
		got := fingerprintOf(c)
		assert.NotEqualf(t, base, got,
			"mutating %q did not change the fingerprint — field not covered by fingerprint", m.name)
		if prev, ok := seen[got]; ok {
			t.Errorf("mutation %q collides with %q (same fingerprint %s) — label keys not distinct", m.name, prev, got)
		}
		seen[got] = m.name
	}
}

func vxlan(c *TaskConfig) *VxlanOutputConfig { return c.Outputs[0].Vxlan }
func gre(c *TaskConfig) *GreOutputConfig     { return c.Outputs[0].Gre }
func zmq(c *TaskConfig) *ZmqOutputConfig     { return c.Outputs[0].Zmq }
func lp(c *TaskConfig) *LibpcapConfig        { return c.Capturer.Libpcap }
func out0(c *TaskConfig) *OutputConfig       { return &c.Outputs[0] }

// ── capturer / req_pattern fields (output-independent) ──

func TestFingerprint_CapturerAndReqPatternFieldsCovered(t *testing.T) {
	makeBase := func() *TaskConfig { return taskWith(baseZmqOutput()) }
	runMutations(t, makeBase, []mutator{
		{"capturer.libpcap.interface", func(c *TaskConfig) { lp(c).Interface = "eth9" }},
		{"capturer.libpcap.snaplen", func(c *TaskConfig) { lp(c).Snaplen = lo.ToPtr(1500) }},
		{"capturer.libpcap.netns", func(c *TaskConfig) { lp(c).Netns = lo.ToPtr("ns2") }},
		{"capturer.libpcap.bpf", func(c *TaskConfig) { lp(c).Bpf = lo.ToPtr("udp") }},
		{"capturer.libpcap.buffer_size_mb", func(c *TaskConfig) { lp(c).BufferSizeMB = lo.ToPtr[uint64](512) }},
		{"capturer.libpcap.timeout_ms", func(c *TaskConfig) { lp(c).TimeoutMs = lo.ToPtr(200) }},
		{"capturer.libpcap.not_filter_output_hosts", func(c *TaskConfig) { lp(c).NotFilterOutputHosts = lo.ToPtr(false) }},
		{"capturer.libpcap.snaplen->nil", func(c *TaskConfig) { lp(c).Snaplen = nil }},
		{"req_pattern.type", func(c *TaskConfig) { c.ReqPattern.Type = ReqPatternType_AUTO }},
		{"req_pattern.custom.pattern", func(c *TaskConfig) { c.ReqPattern.Custom.Pattern = "host 9.9.9.9" }},
		{"req_pattern->nil", func(c *TaskConfig) { c.ReqPattern = nil }},
	})
}

// ── common OutputConfig fields ──

func TestFingerprint_CommonOutputFieldsCovered(t *testing.T) {
	makeBase := func() *TaskConfig { return taskWith(baseZmqOutput()) }
	runMutations(t, makeBase, []mutator{
		{"output.rate_limit_mbps", func(c *TaskConfig) { out0(c).RateLimitMbps = lo.ToPtr[uint64](999) }},
		{"output.slice", func(c *TaskConfig) { out0(c).Slice = lo.ToPtr[uint64](64) }},
		{"output.rate_limit_mbps->nil", func(c *TaskConfig) { out0(c).RateLimitMbps = nil }},
		{"output.slice->nil", func(c *TaskConfig) { out0(c).Slice = nil }},
	})
}

// ── per output type ──

func TestFingerprint_VxlanFieldsCovered(t *testing.T) {
	makeBase := func() *TaskConfig { return taskWith(baseVxlanOutput()) }
	runMutations(t, makeBase, []mutator{
		{"vxlan.host", func(c *TaskConfig) { vxlan(c).Host = "10.9.9.9" }},
		{"vxlan.port", func(c *TaskConfig) { vxlan(c).Port = lo.ToPtr[int32](4790) }},
		{"vxlan.capture_time", func(c *TaskConfig) { vxlan(c).CaptureTime = lo.ToPtr(false) }},
		{"vxlan.vni1", func(c *TaskConfig) { vxlan(c).Vni1 = lo.ToPtr[uint32](101) }},
		{"vxlan.vni2", func(c *TaskConfig) { vxlan(c).Vni2 = lo.ToPtr[uint32](201) }},
		{"vxlan.bind_device", func(c *TaskConfig) { vxlan(c).BindDevice = lo.ToPtr("eth2") }},
		{"vxlan.pmtudisc", func(c *TaskConfig) { vxlan(c).Pmtudisc = lo.ToPtr("dont") }},
		{"vxlan.split.max_payload_size", func(c *TaskConfig) { vxlan(c).Split.MaxPayloadSize = lo.ToPtr[int32](1200) }},
		{"vxlan.split.recalculate_checksum", func(c *TaskConfig) { vxlan(c).Split.RecalculateChecksum = lo.ToPtr(false) }},
		{"vxlan.split->nil", func(c *TaskConfig) { vxlan(c).Split = nil }},
	})
}

func TestFingerprint_GreFieldsCovered(t *testing.T) {
	makeBase := func() *TaskConfig { return taskWith(baseGreOutput()) }
	runMutations(t, makeBase, []mutator{
		{"gre.host", func(c *TaskConfig) { gre(c).Host = "10.9.9.9" }},
		{"gre.service_tag", func(c *TaskConfig) { gre(c).ServiceTag = lo.ToPtr[uint32](3457) }},
		{"gre.bind_device", func(c *TaskConfig) { gre(c).BindDevice = lo.ToPtr("eth2") }},
		{"gre.pmtudisc", func(c *TaskConfig) { gre(c).Pmtudisc = lo.ToPtr("dont") }},
	})
}

func TestFingerprint_ZmqFieldsCovered(t *testing.T) {
	makeBase := func() *TaskConfig { return taskWith(baseZmqOutput()) }
	runMutations(t, makeBase, []mutator{
		{"zmq.host", func(c *TaskConfig) { zmq(c).Host = "10.9.9.9" }},
		{"zmq.port", func(c *TaskConfig) { zmq(c).Port = 5556 }},
		{"zmq.hwm", func(c *TaskConfig) { zmq(c).Hwm = lo.ToPtr(3000) }},
		{"zmq.service_tag", func(c *TaskConfig) { zmq(c).ServiceTag = lo.ToPtr[uint32](8) }},
		{"zmq.uuid", func(c *TaskConfig) { zmq(c).Uuid = "u-2" }},
		{"zmq.heartbeat_ms", func(c *TaskConfig) { zmq(c).HeartbeatMs = lo.ToPtr[int32](3000) }},
		{"zmq.heartbeat_ms->nil", func(c *TaskConfig) { zmq(c).HeartbeatMs = nil }},
	})
}

func TestFingerprint_FileFieldsCovered(t *testing.T) {
	makeBase := func() *TaskConfig { return taskWith(baseFileOutput()) }
	runMutations(t, makeBase, []mutator{
		{"file.name", func(c *TaskConfig) { c.Outputs[0].File.Name = "other.pcap" }},
	})
}

func TestFingerprint_RotatingFileFieldsCovered(t *testing.T) {
	makeBase := func() *TaskConfig { return taskWith(baseRotatingFileOutput()) }
	runMutations(t, makeBase, []mutator{
		{"rotating_file.file_root", func(c *TaskConfig) { c.Outputs[0].RotatingFile.FileRoot = "/var/cap" }},
		{"rotating_file.max_file_interval", func(c *TaskConfig) { c.Outputs[0].RotatingFile.MaxFileInterval = lo.ToPtr[int32](120) }},
	})
}

// ── structural invariants ──

// The fingerprint must be stable: identical configs hash identically, and the
// same config hashes the same across repeated calls.
func TestFingerprint_Deterministic(t *testing.T) {
	c1 := taskWith(baseVxlanOutput())
	c2 := taskWith(baseVxlanOutput())
	assert.Equal(t, fingerprintOf(c1), fingerprintOf(c2), "identical configs must produce identical fingerprints")
	assert.Equal(t, fingerprintOf(c1), fingerprintOf(c1), "fingerprint must be stable across calls")
}

// The Fingerprint field itself must NOT feed back into its own computation
// (the reflection refactor must exclude it), otherwise it is unstable by construction.
func TestFingerprint_ExcludesFingerprintField(t *testing.T) {
	c := taskWith(baseZmqOutput())
	want := fingerprintOf(c)
	c.Fingerprint = lo.ToPtr("anything")
	assert.Equal(t, want, fingerprintOf(c), "TaskConfig.Fingerprint must not affect fingerprint computation")
}

// Output ordering is significant: two tasks with the same outputs in a different
// order are different tasks and must not be treated as identical on reload.
func TestFingerprint_OutputOrderSignificant(t *testing.T) {
	a := &TaskConfig{
		Capturer: CapturerConfig{Type: CapturerType_Libpcap, Libpcap: baseLibpcap()},
		Outputs:  []OutputConfig{baseZmqOutput(), baseGreOutput()},
	}
	b := &TaskConfig{
		Capturer: CapturerConfig{Type: CapturerType_Libpcap, Libpcap: baseLibpcap()},
		Outputs:  []OutputConfig{baseGreOutput(), baseZmqOutput()},
	}
	assert.NotEqual(t, fingerprintOf(a), fingerprintOf(b), "output order must affect the fingerprint")
}

// Adding an output changes identity (different number of outputs).
func TestFingerprint_OutputCountSignificant(t *testing.T) {
	one := taskWith(baseZmqOutput())
	two := taskWith(baseZmqOutput())
	two.Outputs = append(two.Outputs, baseGreOutput())
	assert.NotEqual(t, fingerprintOf(one), fingerprintOf(two), "adding an output must change the fingerprint")
}
