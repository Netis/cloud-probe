package cpworker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var sockSeq atomic.Uint64

// shortSocketPath returns a unix-socket path short enough to fit in
// sun_path (104 bytes on macOS, 108 on Linux). t.TempDir() paths on macOS
// often exceed the limit because of the long test-name suffix.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	n := sockSeq.Add(1)
	p := fmt.Sprintf("/tmp/cpw-%d-%d.sock", os.Getpid(), n)
	_ = os.Remove(p)
	t.Cleanup(func() { _ = os.Remove(p) })
	return p
}

// fakeServer mimics the cpworker unix socket: handshake then JSON
// request/response, one record per line.
type fakeServer struct {
	t        *testing.T
	socket   string
	handlers map[string]func(args map[string]any) (map[string]any, error)
	wg       sync.WaitGroup
	listener net.Listener
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets not portable to windows test runners")
	}
	s := &fakeServer{
		t:        t,
		socket:   shortSocketPath(t),
		handlers: map[string]func(map[string]any) (map[string]any, error){},
	}
	ln, err := net.Listen("unix", s.socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.listener = ln
	s.wg.Add(1)
	go s.acceptLoop()
	return s
}

func (s *fakeServer) connStr() string { return "unix://" + s.socket }

func (s *fakeServer) Close() {
	_ = s.listener.Close()
	_ = os.Remove(s.socket)
	s.wg.Wait()
}

func (s *fakeServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			s.serve(c)
		}(conn)
	}
}

func (s *fakeServer) serve(conn net.Conn) {
	r := bufio.NewReader(conn)
	// handshake
	line, err := r.ReadBytes('\n')
	if err != nil {
		return
	}
	var hs map[string]any
	if err := json.Unmarshal(line, &hs); err != nil {
		return
	}
	if _, ok := hs["version"]; !ok {
		return
	}
	resp, _ := json.Marshal(map[string]string{"status": "OK"})
	resp = append(resp, '\n')
	if _, err := conn.Write(resp); err != nil {
		return
	}

	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var req map[string]any
		if err := json.Unmarshal(line, &req); err != nil {
			return
		}
		cmd, _ := req["command"].(string)
		args, _ := req["arguments"].(map[string]any)

		var out map[string]any
		h, ok := s.handlers[cmd]
		if !ok {
			out = map[string]any{"status": "ERROR", "message": "unknown command"}
		} else {
			body, err := h(args)
			if err != nil {
				out = map[string]any{"status": "ERROR", "message": err.Error()}
			} else {
				if body == nil {
					body = map[string]any{}
				}
				body["status"] = "OK"
				out = body
			}
		}
		buf, _ := json.Marshal(out)
		buf = append(buf, '\n')
		if _, err := conn.Write(buf); err != nil {
			return
		}
	}
}

func TestUnixClient_Ping(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	srv.handlers["ping"] = func(args map[string]any) (map[string]any, error) {
		return map[string]any{"ts_ms": time.Now().UnixMilli()}, nil
	}

	client, err := NewClient(srv.connStr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	res, err := client.Ping(context.Background())
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	if res.Rtt <= 0 {
		t.Errorf("RTT should be > 0, got %v", res.Rtt)
	}
	if res.When.IsZero() {
		t.Errorf("When should be set")
	}
}

func TestUnixClient_Info(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	srv.handlers["info"] = func(args map[string]any) (map[string]any, error) {
		return map[string]any{
			"version":         "0.9.x-test",
			"pid":             4321,
			"uptime_sec":      120,
			"config_path":     "/tmp/cpworker.json",
			"log_destination": "stderr",
			"started_at_sec":  1700000000,
		}, nil
	}

	client, err := NewClient(srv.connStr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	info, err := client.Info(context.Background())
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if info.Version != "0.9.x-test" {
		t.Errorf("version: got %q", info.Version)
	}
	if info.Pid != 4321 {
		t.Errorf("pid: got %d", info.Pid)
	}
	if info.UptimeSec != 120 {
		t.Errorf("uptime_sec: got %d", info.UptimeSec)
	}
	if info.ConfigPath != "/tmp/cpworker.json" {
		t.Errorf("config_path: got %q", info.ConfigPath)
	}
	if info.LogDestination != "stderr" {
		t.Errorf("log_destination: got %q", info.LogDestination)
	}
	if info.StartedAtSec != 1700000000 {
		t.Errorf("started_at_sec: got %d", info.StartedAtSec)
	}
}

func TestUnixClient_UnknownCommand(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()
	// no handlers registered

	client, err := NewClient(srv.connStr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Ping(context.Background()); err == nil {
		t.Error("expected error for unknown command")
	}
}

func TestUnixClient_BadConnStr(t *testing.T) {
	if _, err := NewClient("not a url"); err == nil {
		t.Error("expected error for malformed connStr")
	}
	if _, err := NewClient("tcp://1.2.3.4:5"); err == nil {
		t.Error("expected error for unsupported scheme")
	}
}

// TestUnixClient_HonorsContextDeadline proves the --timeout fix: a client
// built with a large defaultTimeout must still honor a short ctx deadline
// supplied by the caller. The fake server deliberately stalls a handler so
// the client can only return within the deadline if SetReadDeadline picked
// up ctx.Deadline().
func TestUnixClient_HonorsContextDeadline(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	release := make(chan struct{})
	srv.handlers["ping"] = func(args map[string]any) (map[string]any, error) {
		<-release // block the handler until the test finishes
		return map[string]any{"ts_ms": time.Now().UnixMilli()}, nil
	}
	defer close(release)

	// Large fallback timeout — if the ctx deadline is ignored the test
	// would hang for 30s and fail on go test's own timeout.
	client, err := NewClientWithTimeout(srv.connStr(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = client.Ping(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Ping to error out before 30s default timeout")
	}
	if elapsed > 2*time.Second {
		t.Errorf("ctx deadline not propagated: elapsed=%v (expected ~100ms)", elapsed)
	}
}

// TestUnixClient_DefaultTimeoutApplies confirms the fallback path: when the
// caller supplies a deadline-less context, defaultTimeout bounds the read.
func TestUnixClient_DefaultTimeoutApplies(t *testing.T) {
	srv := newFakeServer(t)
	defer srv.Close()

	release := make(chan struct{})
	srv.handlers["ping"] = func(args map[string]any) (map[string]any, error) {
		<-release
		return map[string]any{}, nil
	}
	defer close(release)

	client, err := NewClientWithTimeout(srv.connStr(), 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	start := time.Now()
	_, err = client.Ping(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Ping to time out using defaultTimeout")
	}
	if elapsed > 2*time.Second {
		t.Errorf("defaultTimeout did not apply: elapsed=%v", elapsed)
	}
}
