package integration

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// controlIOTimeout bounds every read and write a test client makes on the control socket.
const controlIOTimeout = 3 * time.Second

// startControlWorker starts cpworker with a control socket and a pcap_file task feeding
// a null output, and returns the socket path once the worker is polling.
func startControlWorker(t *testing.T, name string) string {
	t.Helper()
	out := setupTestOutputDir(t, filepath.Join("control_socket", name))

	// sun_path holds at most 108 bytes, and the output directory is deep, so the
	// socket goes in a short temp directory.
	sockDir, err := os.MkdirTemp("", "cpw")
	if err != nil {
		t.Fatalf("create socket dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "ctl.sock")

	pcapPath, err := filepath.Abs(filepath.Join(getTestDataDir(), "pcaps", "http.pcap"))
	if err != nil {
		t.Fatalf("resolve pcap path: %v", err)
	}
	cfgMap := map[string]any{
		"control": map[string]any{"type": "unix", "unix": map[string]any{"path": sock}},
		"tasks": []map[string]any{{
			"fingerprint": "ctl",
			"capturer":    map[string]any{"type": "pcap_file", "pcap_file": map[string]any{"file_name": pcapPath}},
			"outputs":     []map[string]any{{"type": "null"}},
		}},
	}
	data, err := json.MarshalIndent(cfgMap, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	conf := filepath.Join(out, "config.json")
	if err := os.WriteFile(conf, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, logp, _ := startReloadWorker(t, out, conf)
	if !waitForLog(t, logp, "start poll packets", 5*time.Second) {
		t.Fatalf("worker did not start polling; log:\n%s", readLog(logp))
	}
	return sock
}

// controlConn is a control-socket client that frames replies by newline, as
// cpgolib/cpworker/unix_client.go does.
type controlConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialControl(sock string) (*controlConn, error) {
	conn, err := net.DialTimeout("unix", sock, controlIOTimeout)
	if err != nil {
		return nil, err
	}
	return &controlConn{conn: conn, r: bufio.NewReader(conn)}, nil
}

// send writes each part with a separate write call, pausing gap between them.
func (c *controlConn) send(gap time.Duration, parts ...string) error {
	for i, p := range parts {
		if i > 0 {
			time.Sleep(gap)
		}
		c.conn.SetWriteDeadline(time.Now().Add(controlIOTimeout))
		if _, err := c.conn.Write([]byte(p)); err != nil {
			return err
		}
	}
	return nil
}

// expectOK reads one reply line and checks that its status is OK.
func (c *controlConn) expectOK() error {
	c.conn.SetReadDeadline(time.Now().Add(controlIOTimeout))
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read reply: %w", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("decode reply %q: %w", line, err)
	}
	if resp["status"] != "OK" {
		return fmt.Errorf("reply status is not OK: %s", line)
	}
	return nil
}

// handshakeAndPing runs the v1 handshake and one ping on a new connection.
func handshakeAndPing(sock string) error {
	c, err := dialControl(sock)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.conn.Close()
	if err := c.send(0, `{"version":"v1"}`+"\n"); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}
	if err := c.expectOK(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if err := c.send(0, `{"command":"ping"}`+"\n"); err != nil {
		return fmt.Errorf("send ping: %w", err)
	}
	if err := c.expectOK(); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	return nil
}

// TestControlSocket checks the cpworker control socket against the clients that use
// it: cpctl and cpdaemon, through cpgolib/cpworker/unix_client.go. That client sends
// one request and waits for its reply before sending the next.
//
//   - concurrent_clients:       clients that connect at the same time are all served (#260)
//   - request_split_across_writes: a request that arrives in several writes is answered (#261)
//   - silent_client_does_not_block_others: a client that connects and never sends the
//     handshake does not stop the manager from serving other clients
func TestControlSocket(t *testing.T) {
	if os.Getenv("CPWORKER_BIN") == "" {
		t.Skip("CPWORKER_BIN not set")
	}

	t.Run("concurrent_clients", func(t *testing.T) {
		sock := startControlWorker(t, "concurrent_clients")

		const clients = 32
		errs := make(chan error, clients)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < clients; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				if err := handshakeAndPing(sock); err != nil {
					errs <- fmt.Errorf("client %d: %w", i, err)
				}
			}(i)
		}
		close(start)
		wg.Wait()
		close(errs)

		failed := 0
		for err := range errs {
			failed++
			t.Log(err)
		}
		if failed > 0 {
			t.Errorf("%d of %d concurrent clients failed", failed, clients)
		}
	})

	t.Run("request_split_across_writes", func(t *testing.T) {
		sock := startControlWorker(t, "request_split")

		c, err := dialControl(sock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.conn.Close()
		if err := c.send(0, `{"version":"v1"}`+"\n"); err != nil {
			t.Fatalf("send handshake: %v", err)
		}
		if err := c.expectOK(); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		// The gap is well inside the manager's 3 x 500 ms wait for the rest of a request.
		if err := c.send(100*time.Millisecond, `{"command":`, `"ping"}`+"\n"); err != nil {
			t.Fatalf("send split ping: %v", err)
		}
		if err := c.expectOK(); err != nil {
			t.Errorf("split ping: %v", err)
		}
	})

	t.Run("silent_client_does_not_block_others", func(t *testing.T) {
		sock := startControlWorker(t, "silent_client")

		silent, err := dialControl(sock)
		if err != nil {
			t.Fatalf("dial silent client: %v", err)
		}
		defer silent.conn.Close()
		time.Sleep(100 * time.Millisecond) // let the manager accept it first

		// The silent client stays connected for the whole check.
		if err := handshakeAndPing(sock); err != nil {
			t.Errorf("client behind a silent connection: %v", err)
		}
	})
}
