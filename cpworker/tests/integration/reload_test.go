package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netis-cloud-probe/cloud-probe/cpworker/tests/integration/helpers"
)

// reloadUDPPort is the loopback UDP port the Tier 2 test sends traffic to.
// It MUST match the `"bpf": "udp and port 54321"` filter in the
// testdata/reload/*_dest_*.json capturer configs (kept in sync by hand —
// those files are strict JSON and cannot carry a cross-reference comment).
const reloadUDPPort = 54321

// cfg returns the path to a static reload config by file name.
func cfg(name string) string { return filepath.Join("testdata", "reload", name) }

// startReloadWorker copies srcConfig to <outputDir>/active.json, starts cpworker against
// it, and returns the runner, the stderr-log path, and the active-config path.
func startReloadWorker(t *testing.T, outputDir, srcConfig string) (*helpers.CpworkerRunner, string, string) {
	t.Helper()
	active := filepath.Join(outputDir, "active.json")
	if err := copyFile(srcConfig, active); err != nil {
		t.Fatalf("copy config %s: %v", srcConfig, err)
	}
	stderrFile, err := os.Create(filepath.Join(outputDir, "cpworker_stderr.log"))
	if err != nil {
		t.Fatalf("create stderr log: %v", err)
	}
	stdoutFile, err := os.Create(filepath.Join(outputDir, "cpworker_stdout.log"))
	if err != nil {
		stderrFile.Close()
		t.Fatalf("create stdout log: %v", err)
	}
	runner, err := helpers.NewCpworkerRunner(active, 60*time.Second)
	if err != nil {
		stderrFile.Close()
		stdoutFile.Close()
		t.Fatalf("new runner: %v", err)
	}
	runner.SetStderr(stderrFile)
	runner.SetStdout(stdoutFile)
	if err := runner.Start(); err != nil {
		stderrFile.Close()
		stdoutFile.Close()
		t.Fatalf("start cpworker: %v", err)
	}
	t.Cleanup(func() {
		if runner.Running() {
			runner.Stop()
		}
		stderrFile.Close()
		stdoutFile.Close()
	})
	return runner, filepath.Join(outputDir, "cpworker_stderr.log"), active
}

// reloadTo overwrites the active config with srcConfig and signals reload.
func reloadTo(t *testing.T, runner *helpers.CpworkerRunner, active, srcConfig string) {
	t.Helper()
	if err := copyFile(srcConfig, active); err != nil {
		t.Fatalf("copy config %s: %v", srcConfig, err)
	}
	if err := runner.Reload(); err != nil {
		t.Fatalf("reload signal: %v", err)
	}
}

// TestReload exercises cpworker's SIGHUP config reload end-to-end. Each subtest
// targets one reload behaviour and runs under both execution models (rtc and
// pipeline) where applicable:
//   - rebuild_on_fingerprint_change: changed fingerprint -> old task reclaimed, new built
//   - reuse_on_no_change:            identical config    -> task reused, nothing reclaimed
//   - abort_on_invalid_config:       bad config          -> reload aborts, old config kept
//   - switch_output_destination:     reload swaps the output file; pre/post-reload traffic
//                                     must land in the old/new file respectively
//   - pipeline_buffer_resize:        reload changes the pipeline ring size (applied live)
//
// The first three assert on cpworker's log; switch_output_destination asserts on
// captured packets (the real drain/ordering check under pipeline).
func TestReload(t *testing.T) {
	if os.Getenv("CPWORKER_BIN") == "" {
		t.Skip("CPWORKER_BIN not set")
	}
	// The log-asserting subtests don't inspect their captured output; it all goes
	// to this throwaway dir.
	if err := os.MkdirAll(filepath.Join(getOutputDir(), "reload", "_scratch"), 0o755); err != nil {
		t.Fatalf("mkdir scratch: %v", err)
	}

	t.Run("rebuild_on_fingerprint_change", func(t *testing.T) {
		cases := []struct {
			name, before, after string
			pipeline            bool
		}{
			{"rtc", "rtc_rebuild_before.json", "rtc_rebuild_after.json", false},
			{"pipeline", "pipeline_rebuild_before.json", "pipeline_rebuild_after.json", true},
		}
		for _, c := range cases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				out := setupTestOutputDir(t, "reload/rebuild_"+c.name)
				runner, logp, active := startReloadWorker(t, out, cfg(c.before))
				if !waitForLog(t, logp, "reload thread started", 5*time.Second) {
					t.Fatalf("reload thread did not start; log:\n%s", readLog(logp))
				}
				reloadTo(t, runner, active, cfg(c.after))
				if !waitForLog(t, logp, "[main] reload complete", 10*time.Second) {
					t.Fatalf("reload did not complete (possible deadlock); log:\n%s", readLog(logp))
				}
				if !logContains(logp, "reclaim unused task, fingerprint=alpha") {
					t.Errorf("expected alpha task reclaimed; log:\n%s", readLog(logp))
				}
				if c.pipeline && !logContains(logp, "drain output ring before reclaiming old tasks") {
					t.Errorf("expected pipeline drain; log:\n%s", readLog(logp))
				}
				if !runner.Running() {
					t.Error("cpworker died across reload")
				}
			})
		}
	})

	t.Run("reuse_on_no_change", func(t *testing.T) {
		cases := []struct {
			name, conf string
			pipeline   bool
		}{
			{"rtc", "rtc_reuse.json", false},
			{"pipeline", "pipeline_reuse.json", true},
		}
		for _, c := range cases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				out := setupTestOutputDir(t, "reload/reuse_"+c.name)
				runner, logp, active := startReloadWorker(t, out, cfg(c.conf))
				if !waitForLog(t, logp, "reload thread started", 5*time.Second) {
					t.Fatalf("reload thread did not start; log:\n%s", readLog(logp))
				}
				reloadTo(t, runner, active, cfg(c.conf)) // identical config -> reuse
				if !waitForLog(t, logp, "[main] reload complete", 10*time.Second) {
					t.Fatalf("reload did not complete (possible deadlock); log:\n%s", readLog(logp))
				}
				if !logContains(logp, "existing task-0, fingerprint=alpha") {
					t.Errorf("expected task reused; log:\n%s", readLog(logp))
				}
				if logContains(logp, "reclaim unused task") {
					t.Errorf("unexpected reclaim on no-change reload; log:\n%s", readLog(logp))
				}
				if c.pipeline && !logContains(logp, "drain output ring before reclaiming old tasks") {
					t.Errorf("expected pipeline drain; log:\n%s", readLog(logp))
				}
				if !runner.Running() {
					t.Error("cpworker died across reload")
				}
			})
		}
	})

	t.Run("abort_on_invalid_config", func(t *testing.T) {
		cases := []struct{ name, before string }{
			{"rtc", "rtc_rebuild_before.json"},
			{"pipeline", "pipeline_rebuild_before.json"},
		}
		for _, c := range cases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				out := setupTestOutputDir(t, "reload/invalid_"+c.name)
				runner, logp, active := startReloadWorker(t, out, cfg(c.before))
				if !waitForLog(t, logp, "reload thread started", 5*time.Second) {
					t.Fatalf("reload thread did not start; log:\n%s", readLog(logp))
				}
				reloadTo(t, runner, active, cfg("broken.json"))
				if !waitForLog(t, logp, "parse config failed", 5*time.Second) {
					t.Fatalf("expected parse failure; log:\n%s", readLog(logp))
				}
				// Wait for the main thread's error acknowledgement — the last thing logged
				// before reload returns to IDLE without completing. This makes the
				// "did not complete" check structural rather than time-based.
				if !waitForLog(t, logp, "[main] reload thread reported error during config parse", 5*time.Second) {
					t.Fatalf("expected main-thread error ack; log:\n%s", readLog(logp))
				}
				if logContains(logp, "[main] reload complete") {
					t.Errorf("reload should have aborted, not completed; log:\n%s", readLog(logp))
				}
				if !runner.Running() {
					t.Error("cpworker died on bad reload config (should keep old config)")
				}
			})
		}
	})

	t.Run("switch_output_destination", func(t *testing.T) {
		cases := []struct {
			name, dirName, confA, confB string
		}{
			{"rtc", "switch_rtc", "rtc_dest_a.json", "rtc_dest_b.json"},
			{"pipeline", "switch_pipeline", "pipeline_dest_a.json", "pipeline_dest_b.json"},
		}
		for _, c := range cases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				out := setupTestOutputDir(t, "reload/"+c.dirName)
				aPcap := filepath.Join(out, "a.pcap")
				bPcap := filepath.Join(out, "b.pcap")
				addr := fmt.Sprintf("127.0.0.1:%d", reloadUDPPort)

				runner, logp, active := startReloadWorker(t, out, cfg(c.confA))
				if !waitForLog(t, logp, "reload thread started", 5*time.Second) {
					t.Fatalf("reload thread did not start; log:\n%s", readLog(logp))
				}
				time.Sleep(1 * time.Second) // libpcap warmup

				sendUDP(t, addr, markers("BATCH1", 10))
				time.Sleep(1 * time.Second) // capture + write batch1

				reloadTo(t, runner, active, cfg(c.confB))
				if !waitForLog(t, logp, "[main] reload complete", 10*time.Second) {
					t.Fatalf("reload did not complete (possible deadlock); log:\n%s", readLog(logp))
				}
				time.Sleep(500 * time.Millisecond) // new task capturing

				sendUDP(t, addr, markers("BATCH2", 10))
				time.Sleep(1 * time.Second)
				runner.Stop() // flush b.pcap (a.pcap was flushed at reclaim)

				if !pcapHasPayload(t, aPcap, "BATCH1") {
					t.Errorf("a.pcap missing BATCH1 (pre-reload traffic lost)")
				}
				if pcapHasPayload(t, aPcap, "BATCH2") {
					t.Errorf("a.pcap leaked BATCH2 (post-reload traffic in old output)")
				}
				if !pcapHasPayload(t, bPcap, "BATCH2") {
					t.Errorf("b.pcap missing BATCH2 (reload did not switch output)")
				}
				if pcapHasPayload(t, bPcap, "BATCH1") {
					t.Errorf("b.pcap leaked BATCH1 (drain/ordering bug)")
				}
			})
		}
	})

	t.Run("pipeline_buffer_resize", func(t *testing.T) {
		out := setupTestOutputDir(t, "reload/pipeline_buf")
		runner, logp, active := startReloadWorker(t, out, cfg("pipeline_buf64.json"))
		if !waitForLog(t, logp, "reload thread started", 5*time.Second) {
			t.Fatalf("reload thread did not start; log:\n%s", readLog(logp))
		}
		reloadTo(t, runner, active, cfg("pipeline_buf128.json"))
		if !waitForLog(t, logp, "[main] reload complete", 10*time.Second) {
			t.Fatalf("reload did not complete (possible deadlock); log:\n%s", readLog(logp))
		}
		if !logContains(logp, "[main] update pipeline buffer_size") {
			t.Errorf("expected live buffer resize; log:\n%s", readLog(logp))
		}
		if !runner.Running() {
			t.Error("cpworker died across reload")
		}
	})
}
