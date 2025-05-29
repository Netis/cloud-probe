package cpm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

type ClientConfig struct {
	Timeout               time.Duration
	DialTimeout           time.Duration
	ResponseHeaderTimeout time.Duration
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	TLSConfig             *tls.Config
}

func (c *ClientConfig) SetDefaults() {
	if c.Timeout == 0 {
		c.Timeout = 15 * time.Second
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.ResponseHeaderTimeout == 0 {
		c.ResponseHeaderTimeout = 15 * time.Second
	}
	if c.MaxIdleConns == 0 {
		c.MaxIdleConns = 10
	}
	if c.MaxIdleConnsPerHost == 0 {
		c.MaxIdleConnsPerHost = 5
	}
}

func (c ClientConfig) New() *http.Client {
	return &http.Client{
		Timeout: c.Timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: c.DialTimeout,
			}).DialContext,
			ResponseHeaderTimeout: c.ResponseHeaderTimeout,
			MaxIdleConns:          c.MaxIdleConns,
			MaxIdleConnsPerHost:   c.MaxIdleConnsPerHost,
			TLSClientConfig:       c.TLSConfig,
		},
	}
}

type HttpClient struct {
	baseUrl *url.URL
	client  *http.Client
}

func NewHttpClient(baseUrl string, cfg ClientConfig) (*HttpClient, error) {
	cfg.SetDefaults()
	u, err := url.Parse(baseUrl)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &HttpClient{
		baseUrl: u,
		client:  cfg.New(),
	}, nil
}

// 如果重复注册，并且paUUID不相同，会被cpm认为是一个新实例，从而导致问题
// 如果重复注册，并且paUUID相同，会被cpm认为是同一个实例，并更新其他属性
func (c *HttpClient) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	req.FixZero()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	endpoint := c.getEndpoint("/api/v1/daemons")
	resp, err := c.client.Post(endpoint.String(), "application/json", bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer resp.Body.Close()

	if err := c.assert2xx(resp); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "read body error")
	}

	if err := c.checkBodyError(resp.StatusCode, body); err != nil {
		return nil, err
	}

	var res RegisterResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, errors.Wrapf(err, "unmarshal body error")
	}
	return &res, nil
}

func (c *HttpClient) SyncStrategy(ctx context.Context, daemonId int64, version int32) (*SyncStrategyResult, error) {
	endpoint := c.getEndpoint(fmt.Sprintf("/api/v1/daemons/%d/sync/strategy", daemonId))
	query := endpoint.Query()
	query.Add("version", fmt.Sprintf("%d", version))
	endpoint.RawQuery = query.Encode()

	resp, err := c.client.Get(endpoint.String())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "read body error")
		}
		if err := c.checkBodyError(resp.StatusCode, body); err != nil {
			return nil, err
		}
		var res SyncStrategyResponse
		if err := json.Unmarshal(body, &res); err != nil {
			return nil, errors.Wrapf(err, "unmarshal body error")
		}
		return &SyncStrategyResult{
			Changed:  true,
			Response: &res,
		}, nil
	case http.StatusNotModified:
		return &SyncStrategyResult{
			Changed:  false,
			Response: nil,
		}, nil
	default:
		return nil, errors.WithStack(NewHttpRespError(resp))
	}
}

func (c *HttpClient) SyncMetrics(ctx context.Context, daemonId int64, req SyncMetricsRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return errors.WithStack(err)
	}

	endpoint := c.getEndpoint(fmt.Sprintf("/api/v1/daemons/%d/sync/metrics", daemonId))
	resp, err := c.client.Post(endpoint.String(), "application/json", bytes.NewBuffer(data))
	if err != nil {
		return errors.WithStack(err)
	}
	defer resp.Body.Close()

	if err := c.assert2xx(resp); err != nil {
		return err
	}
	discardHttpBody(resp)
	return nil
}

func (c *HttpClient) getEndpoint(endpoint string) *url.URL {
	return c.baseUrl.JoinPath(endpoint)
}

func (c *HttpClient) checkBodyError(statusCode int, body []byte) error {
	var res struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil
	}
	if res.Code >= 400 {
		return errors.WithStack(&HttpBodyError{
			StatusCode: statusCode,
			Code:       res.Code,
			Msg:        res.Msg,
		})
	}
	return nil
}

func (c *HttpClient) assert2xx(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return errors.WithStack(NewHttpRespError(resp))
}

func discardHttpBody(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
}
