package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/netis-cloud-probe/cloud-probe/cpworker/tests/integration/helpers"
)

// Ports for TestIdleCapture. idleCapturePort must never see traffic during a test
// (except the explicit unblock packet in busy_task_not_starved); busyCapturePort
// carries the traffic the busy task is expected to capture.
const (
	idleCapturePort = 54331
	busyCapturePort = 54332
)

// Deadlines for reload and shutdown on an idle link. A stalled worker never
// finishes either, so these only need to exceed a healthy worker's time:
//   - reload: the reload thread polls its mailbox once a second and a reload takes
//     three round trips (PLAN, BUILD, RECLAIM), so up to ~3 s. Same bound as TestReload.
//   - shutdown: the main loop sees the quit flag at once; joining the reload
//     thread takes up to its 1 s poll.
const (
	idleReloadDeadline   = 10 * time.Second
	idleShutdownDeadline = 3 * time.Second
)

type idleTaskSpec struct {
	fingerprint string
	port        int
	output      string         // pcap file path for a file output
	outputCfg   map[string]any // if set, used as the output instead of a file output
}

// writeIdleCaptureConfig writes a cpworker config with one libpcap task on lo per
// spec, each filtered to its own UDP port, and returns its path.
func writeIdleCaptureConfig(t *testing.T, outputDir string, pipeline bool, timeoutMs int, specs []idleTaskSpec) string {
	t.Helper()
	tasks := make([]map[string]any, 0, len(specs))
	for _, s := range specs {
		output := s.outputCfg
		if output == nil {
			output = map[string]any{"type": "file", "file": map[string]any{"name": s.output}}
		}
		tasks = append(tasks, map[string]any{
			"fingerprint": s.fingerprint,
			"capturer": map[string]any{
				"type": "libpcap",
				"libpcap": map[string]any{
					"interface":  "lo",
					"snaplen":    2048,
					"bpf":        fmt.Sprintf("udp and port %d", s.port),
					"timeout_ms": timeoutMs,
					// Test traffic and a zmq output both use 127.0.0.1; the default
					// output-host exclusion would filter all of it out of the capture.
					"not_filter_output_hosts": true,
				},
			},
			"outputs": []map[string]any{output},
		})
	}
	cfgMap := map[string]any{"tasks": tasks}
	if pipeline {
		cfgMap["execution_model"] = "pipeline"
		cfgMap["pipeline"] = map[string]any{"buffer_size_mb": 64}
	}
	data, err := json.MarshalIndent(cfgMap, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	path := filepath.Join(outputDir, "config.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// countPayloads returns how many packets in the pcap file contain any of markers.
func countPayloads(t *testing.T, path string, markers []string) int {
	t.Helper()
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		t.Logf("open pcap %s: %v", path, err)
		return 0
	}
	defer handle.Close()
	n := 0
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		for _, m := range markers {
			if bytes.Contains(pkt.Data(), []byte(m)) {
				n++
				break
			}
		}
	}
	return n
}

// sendUDPPaced sends n datagrams "PREFIX-00000".. to addr with gap between them.
// Unlike sendUDP it formats payloads on the fly, for large n.
func sendUDPPaced(t *testing.T, addr, prefix string, n int, gap time.Duration) {
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
	for i := 0; i < n; i++ {
		if _, err := conn.WriteTo([]byte(fmt.Sprintf("%s-%05d", prefix, i)), raddr); err != nil {
			t.Fatalf("send udp: %v", err)
		}
		time.Sleep(gap)
	}
}

// stopIdleCaptureWorker sends SIGINT, then one packet on the idle port, and waits
// for exit. On a healthy worker the packet lands after exit and is harmless. On a
// worker stalled in the idle task's read (#241) it wakes the loop once so the quit
// flag is seen and outputs are flushed: packet counts then measure capture alone,
// not the shutdown hang.
func stopIdleCaptureWorker(t *testing.T, runner *helpers.CpworkerRunner, logp string) {
	t.Helper()
	if err := runner.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	sendUDP(t, fmt.Sprintf("127.0.0.1:%d", idleCapturePort), []string{"UNBLOCK"})
	if !runner.WaitExit(5 * time.Second) {
		t.Fatalf("worker did not exit; log:\n%s", readLog(logp))
	}
}

// TestIdleCapture checks that a libpcap capturer on a link with no matching
// traffic does not stall cpworker's main loop (issue #241). With TPACKET_V3 and
// timeout_ms > 0, libpcap polls with an infinite timeout and the kernel's block
// retire timer never wakes it for an empty block, so the loop must bound the
// wait itself. timeout_ms == 0 (non-blocking) is the control case.
//
//   - reload:                SIGHUP on an idle link completes the reload
//   - shutdown:              SIGINT on an idle link exits the process
//   - busy_task_not_starved: an idle task does not block a busy task's capture
//   - busy_task_throughput:  an idle task does not throttle a busy task's capture rate
func TestIdleCapture(t *testing.T) {
	if os.Getenv("CPWORKER_BIN") == "" {
		t.Skip("CPWORKER_BIN not set")
	}

	models := []struct {
		name     string
		pipeline bool
	}{
		{"rtc", false},
		{"pipeline", true},
	}
	timeouts := []int{0, 10}

	for _, m := range models {
		for _, timeoutMs := range timeouts {
			m, timeoutMs := m, timeoutMs
			prefix := fmt.Sprintf("%s/timeout_%dms", m.name, timeoutMs)
			dirPrefix := fmt.Sprintf("idle_capture/%s_timeout_%dms", m.name, timeoutMs)

			t.Run(prefix+"/reload", func(t *testing.T) {
				out := setupTestOutputDir(t, dirPrefix+"_reload")
				conf := writeIdleCaptureConfig(t, out, m.pipeline, timeoutMs, []idleTaskSpec{
					{"idle", idleCapturePort, filepath.Join(out, "idle.pcap"), nil},
				})
				runner, logp, active := startReloadWorker(t, out, conf)
				if !waitForLog(t, logp, "start poll packets", 5*time.Second) {
					t.Fatalf("worker did not start polling; log:\n%s", readLog(logp))
				}
				time.Sleep(1 * time.Second) // let the capturer settle into its idle wait

				reloadTo(t, runner, active, conf) // unchanged config -> task reused
				if !waitForLog(t, logp, "[main] reload complete", idleReloadDeadline) {
					t.Fatalf("reload did not complete within %s on an idle link; log:\n%s",
						idleReloadDeadline, readLog(logp))
				}
			})

			t.Run(prefix+"/shutdown", func(t *testing.T) {
				out := setupTestOutputDir(t, dirPrefix+"_shutdown")
				conf := writeIdleCaptureConfig(t, out, m.pipeline, timeoutMs, []idleTaskSpec{
					{"idle", idleCapturePort, filepath.Join(out, "idle.pcap"), nil},
				})
				runner, logp, _ := startReloadWorker(t, out, conf)
				if !waitForLog(t, logp, "start poll packets", 5*time.Second) {
					t.Fatalf("worker did not start polling; log:\n%s", readLog(logp))
				}
				time.Sleep(1 * time.Second)

				if err := runner.Signal(syscall.SIGINT); err != nil {
					t.Fatalf("send SIGINT: %v", err)
				}
				if !runner.WaitExit(idleShutdownDeadline) {
					t.Fatalf("worker did not exit within %s of SIGINT on an idle link; log:\n%s",
						idleShutdownDeadline, readLog(logp))
				}
				if !logContains(logp, "quit") {
					t.Errorf("worker exited without logging quit; log:\n%s", readLog(logp))
				}
			})

			t.Run(prefix+"/busy_task_not_starved", func(t *testing.T) {
				out := setupTestOutputDir(t, dirPrefix+"_starve")
				busyPcap := filepath.Join(out, "busy.pcap")
				conf := writeIdleCaptureConfig(t, out, m.pipeline, timeoutMs, []idleTaskSpec{
					{"idle", idleCapturePort, filepath.Join(out, "idle.pcap"), nil},
					{"busy", busyCapturePort, busyPcap, nil},
				})
				runner, logp, _ := startReloadWorker(t, out, conf)
				if !waitForLog(t, logp, "start poll packets", 5*time.Second) {
					t.Fatalf("worker did not start polling; log:\n%s", readLog(logp))
				}
				time.Sleep(1 * time.Second)

				busy := markers("BUSY", 20)
				sendUDP(t, fmt.Sprintf("127.0.0.1:%d", busyCapturePort), busy)
				time.Sleep(2 * time.Second) // ample time to capture 20 packets
				stopIdleCaptureWorker(t, runner, logp)

				if got := countPayloads(t, busyPcap, busy); got != len(busy) {
					t.Errorf("busy task captured %d of %d packets while another task was idle", got, len(busy))
				}
			})

			// A blocking read on the idle task costs up to timeout_ms per main-loop round
			// even when it does return, and each round takes one packet per task, so the
			// busy task is capped near 1000/timeout_ms pps (~100 pps at 10 ms).
			t.Run(prefix+"/busy_task_throughput", func(t *testing.T) {
				out := setupTestOutputDir(t, dirPrefix+"_throughput")
				busyPcap := filepath.Join(out, "busy.pcap")
				conf := writeIdleCaptureConfig(t, out, m.pipeline, timeoutMs, []idleTaskSpec{
					{"idle", idleCapturePort, filepath.Join(out, "idle.pcap"), nil},
					{"busy", busyCapturePort, busyPcap, nil},
				})
				runner, logp, _ := startReloadWorker(t, out, conf)
				if !waitForLog(t, logp, "start poll packets", 5*time.Second) {
					t.Fatalf("worker did not start polling; log:\n%s", readLog(logp))
				}
				time.Sleep(1 * time.Second)

				const n = 1500
				start := time.Now()
				sendUDPPaced(t, fmt.Sprintf("127.0.0.1:%d", busyCapturePort), "TP", n, time.Millisecond)
				elapsed := time.Since(start)
				time.Sleep(1 * time.Second) // let the tail drain at the capture rate
				stopIdleCaptureWorker(t, runner, logp)

				got := countPayloads(t, busyPcap, []string{"TP-"})
				t.Logf("sent %d in %s (%.0f pps), busy task captured %d", n, elapsed.Round(time.Millisecond),
					float64(n)/elapsed.Seconds(), got)
				if got < n*99/100 {
					t.Errorf("busy task captured %d of %d packets while another task was idle", got, n)
				}
			})
		}
	}
}

// TestIdleZMQFlush checks that a ZMQ output sends a partially filled batch once it
// is older than the 1 s flush limit (docs/ZMQ-WIRE-FORMAT.md §8) while the link is
// idle (issue #253, idle half). The stale-batch check runs from the capturer's
// heartbeat, which a main loop stalled in an idle libpcap read never reaches (#241).
//
// The receiver is stopped before the worker, so the flush-on-destroy path (#253,
// graceful-stop half) cannot deliver the batch: only the idle flush can.
func TestIdleZMQFlush(t *testing.T) {
	if os.Getenv("CPWORKER_BIN") == "" {
		t.Skip("CPWORKER_BIN not set")
	}

	models := []struct {
		name     string
		pipeline bool
	}{
		{"rtc", false},
		{"pipeline", true},
	}
	timeouts := []int{0, 10}
	zmqPort := 19031

	for _, m := range models {
		for _, timeoutMs := range timeouts {
			m, timeoutMs := m, timeoutMs
			port := zmqPort
			zmqPort++
			t.Run(fmt.Sprintf("%s/timeout_%dms", m.name, timeoutMs), func(t *testing.T) {
				out := setupTestOutputDir(t, fmt.Sprintf("idle_zmq_flush/%s_timeout_%dms", m.name, timeoutMs))
				receiver, err := helpers.NewZMQCapturer(fmt.Sprintf("tcp://127.0.0.1:%d", port),
					filepath.Join(out, "zmq_raw.dat"), filepath.Join(out, "zmq_packets.pcap"),
					filepath.Join(out, "zmq_stats.json"), "helpers/zmq_receiver")
				if err != nil {
					t.Fatalf("new zmq receiver: %v", err)
				}
				if err := receiver.Start(); err != nil {
					t.Fatalf("start zmq receiver: %v", err)
				}
				defer receiver.Stop()

				conf := writeIdleCaptureConfig(t, out, m.pipeline, timeoutMs, []idleTaskSpec{{
					fingerprint: "zmq",
					// idleCapturePort, so stopIdleCaptureWorker's wake-up packet reaches
					// this task if the worker is stalled.
					port: idleCapturePort,
					outputCfg: map[string]any{
						"type": "zmq",
						// heartbeat_ms 0: a heartbeat also flushes the batch, which would
						// mask a missing idle flush.
						"zmq": map[string]any{"host": "127.0.0.1", "port": port, "heartbeat_ms": 0},
					},
				}})
				runner, logp, _ := startReloadWorker(t, out, conf)
				if !waitForLog(t, logp, "start poll packets", 5*time.Second) {
					t.Fatalf("worker did not start polling; log:\n%s", readLog(logp))
				}
				time.Sleep(1 * time.Second)

				sendUDP(t, fmt.Sprintf("127.0.0.1:%d", idleCapturePort), markers("ZMQ", 4))
				time.Sleep(3 * time.Second) // idle: the batch is stale after 1-2 s

				receiver.Stop() // writes its stats; the worker is still running
				if got := receiver.GetStats().PacketCount; got != 4 {
					t.Errorf("receiver got %d of 4 packets within 3 s on an idle link", got)
				}
				stopIdleCaptureWorker(t, runner, logp)
			})
		}
	}
}
