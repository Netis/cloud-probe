package cpworker

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

type UnixClient struct {
	socketPath string
	// defaultTimeout applies to any dial/read/write when the caller's ctx
	// has no deadline of its own. When the ctx does have a deadline, that
	// deadline wins so --timeout on the CLI propagates correctly.
	defaultTimeout time.Duration

	mu   sync.Mutex
	conn net.Conn
}

// deadlineFor picks the effective I/O deadline: the ctx deadline if set,
// otherwise now + defaultTimeout. This is the single point where a caller's
// context.WithTimeout becomes a socket-level SetDeadline.
func (c *UnixClient) deadlineFor(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(c.defaultTimeout)
}

func (c *UnixClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.closeConn(c.conn)
		c.conn = nil
		return err
	}
	return nil
}

func (c *UnixClient) closeConn(conn net.Conn) error {
	if err := conn.Close(); err != nil {
		return errors.Wrapf(err, "close connection failed")
	}
	return nil
}

func (c *UnixClient) Dial(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return nil
	}

	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

func (c *UnixClient) dial(ctx context.Context) (net.Conn, error) {
	// If the caller didn't supply a deadline, apply defaultTimeout to the
	// dial. If they did, DialContext already honors it.
	dctx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, c.defaultTimeout)
		defer cancel()
	}

	var d net.Dialer
	conn, err := d.DialContext(dctx, "unix", c.socketPath)
	if err != nil {
		return nil, errors.Wrapf(err, "dial %s failed", c.socketPath)
	}

	if err := c.handshake(ctx, conn); err != nil {
		if cErr := c.closeConn(conn); cErr != nil {
			return nil, multierr.Append(err, cErr)
		}
		return nil, err
	}

	return conn, nil
}

func (c *UnixClient) handshake(ctx context.Context, conn net.Conn) error {
	cmdData, err := json.Marshal(map[string]string{
		"version": "v1",
	})
	if err != nil {
		return errors.Wrapf(err, "marshal handshake data failed")
	}
	cmdData = append(cmdData, '\n')

	if err := c.send(ctx, conn, cmdData); err != nil {
		return errors.Wrapf(err, "write handshake data failed")
	}

	data, err := c.recv(ctx, conn)
	if err != nil {
		return err
	}

	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		return errors.Wrapf(err, "invalid response")
	}

	if resp["status"] != "OK" {
		return errors.Errorf("No OK response: %v", resp)
	}
	return nil
}

func (c *UnixClient) CollectStatsSummary(ctx context.Context) (StatsSummary, error) {
	resp, err := c.RunCommand(ctx, "collect_stats_summary", nil)
	if err != nil {
		return StatsSummary{}, err
	}

	var stats StatsSummary
	if err := mapstructure.Decode(resp, &stats); err != nil {
		return StatsSummary{}, errors.Wrapf(err, "invalid stats summary")
	}
	return stats, nil
}

func (c *UnixClient) Ping(ctx context.Context) (PingResult, error) {
	start := time.Now()
	if _, err := c.RunCommand(ctx, "ping", nil); err != nil {
		return PingResult{}, err
	}
	return PingResult{
		Rtt:  time.Since(start),
		When: start,
	}, nil
}

func (c *UnixClient) Info(ctx context.Context) (InfoSummary, error) {
	resp, err := c.RunCommand(ctx, "info", nil)
	if err != nil {
		return InfoSummary{}, err
	}

	var info InfoSummary
	if err := mapstructure.Decode(resp, &info); err != nil {
		return InfoSummary{}, errors.Wrapf(err, "invalid info summary")
	}
	return info, nil
}

func (c *UnixClient) ReloadConfig(ctx context.Context) error {
	_, err := c.RunCommand(ctx, "reload_config", nil)
	return err
}

func (c *UnixClient) RunCommand(ctx context.Context, command string, arguments map[string]any) (map[string]any, error) {
	var err error

	c.mu.Lock()
	conn := c.conn
	if conn == nil {
		conn, err = c.dial(ctx)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		c.conn = conn
	}
	c.mu.Unlock()

	cmd := map[string]any{
		"command": command,
	}
	if len(arguments) != 0 {
		cmd["arguments"] = arguments
	}
	cmdData, err := json.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	cmdData = append(cmdData, '\n')

	if err := c.send(ctx, conn, cmdData); err != nil {
		cErr := c.Close()
		return nil, multierr.Append(errors.Wrapf(err, "write command data failed"), cErr)
	}

	data, err := c.recv(ctx, conn)
	if err != nil {
		cErr := c.Close()
		return nil, multierr.Append(err, cErr)
	}

	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		cErr := c.Close()
		return nil, multierr.Append(errors.Wrapf(err, "invalid response"), cErr)
	}

	if resp["status"] != "OK" {
		return nil, errors.Errorf("No OK response: %v", resp)
	}
	return resp, nil
}

func (c *UnixClient) send(ctx context.Context, conn net.Conn, data []byte) error {
	conn.SetWriteDeadline(c.deadlineFor(ctx))
	_, err := conn.Write(data)
	return err
}

func (c *UnixClient) recv(ctx context.Context, conn net.Conn) ([]byte, error) {
	// Read until '\n' shows up or there was an error. A lot of data
	// is retuned, so may read short.
	reader := bufio.NewReader(conn)
	var response []byte
	for {
		conn.SetReadDeadline(c.deadlineFor(ctx))

		data, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, errors.Wrapf(err, "read response error")
		}

		response = append(response, data...)
		if len(data) > 0 && data[len(data)-1] == '\n' {
			break
		}
	}
	return response, nil
}
