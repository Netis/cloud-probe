package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/slogx"
)

func NewClient(socketPath string) (*Client, error) {
	socketPath = filepath.Clean(socketPath)
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, errors.Wrapf(err, "create dir %s failed", dir)
	}
	return &Client{
		socketPath:   socketPath,
		dailTimeout:  3 * time.Second,
		writeTimeout: 3 * time.Second,
		readTimeout:  3 * time.Second,
	}, nil
}

type Client struct {
	socketPath   string
	dailTimeout  time.Duration
	writeTimeout time.Duration
	readTimeout  time.Duration

	mu   sync.Mutex
	conn net.Conn
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.closeConn(c.conn)
		c.conn = nil
	}
}

func (c *Client) closeConn(conn net.Conn) {
	if err := conn.Close(); err != nil {
		slog.Default().Error("close connection failed", slogx.Error(err))
	} else {
		slog.Default().Info("close connection success")
	}
}

func (c *Client) Dial(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return nil
	}

	conn, err := c.dial()
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

func (c *Client) dial() (net.Conn, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.dailTimeout)
	if err != nil {
		return nil, errors.Wrapf(err, "dail %s failed", c.socketPath)
	}

	if err := c.handshake(conn); err != nil {
		c.closeConn(conn)
		return nil, err
	}

	return conn, nil
}

func (c *Client) handshake(conn net.Conn) error {
	cmdData, err := json.Marshal(map[string]string{
		"version": "v1",
	})
	if err != nil {
		return errors.Wrapf(err, "marshal handshake data failed")
	}
	cmdData = append(cmdData, '\n')

	if err := c.send(conn, cmdData); err != nil {
		return errors.Wrapf(err, "write handshake data failed")
	}

	data, err := c.recv(conn)
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

func (c *Client) RunCommand(ctx context.Context, command string, arguments map[string]any) (map[string]any, error) {
	var err error

	c.mu.Lock()
	conn := c.conn
	if conn == nil {
		conn, err = c.dial()
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

	if err := c.send(conn, cmdData); err != nil {
		c.Close()
		return nil, errors.Wrapf(err, "write command data failed")
	}

	data, err := c.recv(conn)
	if err != nil {
		c.Close()
		return nil, err
	}

	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		c.Close()
		return nil, errors.Wrapf(err, "invalid response")
	}

	if resp["status"] != "OK" {
		return nil, errors.Errorf("No OK response: %v", resp)
	}
	return resp, nil
}

func (c *Client) send(conn net.Conn, data []byte) error {
	conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	_, err := conn.Write(data)
	return err
}

func (c *Client) recv(conn net.Conn) ([]byte, error) {
	// Read until '\n' shows up or there was an error. A lot of data
	// is retuned, so may read short.
	reader := bufio.NewReader(conn)
	var response []byte
	for {
		conn.SetReadDeadline(time.Now().Add(c.readTimeout))

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
