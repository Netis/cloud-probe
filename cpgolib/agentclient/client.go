package agentclient

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

func New(socketPath string) (*Client, error) {
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

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.closeConn(c.conn)
		c.conn = nil
		return err
	}
	return nil
}

func (c *Client) closeConn(conn net.Conn) error {
	if err := conn.Close(); err != nil {
		return errors.Wrapf(err, "close connection failed")
	}
	return nil
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
		if cErr := c.closeConn(conn); cErr != nil {
			return nil, multierr.Append(err, cErr)
		}
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

func (c *Client) CollectStats(ctx context.Context) (Stats, error) {
	resp, err := c.RunCommand(ctx, "collect_stats", nil)
	if err != nil {
		return Stats{}, err
	}

	var stats Stats
	if err := mapstructure.Decode(resp, &stats); err != nil {
		return Stats{}, errors.Wrapf(err, "invalid stats")
	}
	return stats, nil
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
		cErr := c.Close()
		return nil, multierr.Append(errors.Wrapf(err, "write command data failed"), cErr)
	}

	data, err := c.recv(conn)
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
