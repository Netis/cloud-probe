package cpworker

import (
	"context"
	"strings"
	"time"

	"github.com/pkg/errors"
)

func NewClient(connStr string) (Client, error) {
	typ, addr, ok := strings.Cut(connStr, "://")
	if !ok {
		return nil, errors.Errorf("invalid connStr: %s", connStr)
	}
	switch typ {
	case "unix":
		return &UnixClient{
			socketPath:   addr,
			dailTimeout:  3 * time.Second,
			writeTimeout: 3 * time.Second,
			readTimeout:  3 * time.Second,
		}, nil
	}
	return nil, errors.Errorf("invalid connStr: %s", connStr)
}

type Client interface {
	Close() error
	Dial(context.Context) error
	CollectStatsSummary(context.Context) (StatsSummary, error)
}
