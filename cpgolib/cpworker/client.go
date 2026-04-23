package cpworker

import (
	"context"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// DefaultTimeout is the fallback I/O timeout used by clients when the caller's
// context has no deadline of its own.
const DefaultTimeout = 3 * time.Second

func NewClient(connStr string) (Client, error) {
	return NewClientWithTimeout(connStr, DefaultTimeout)
}

// NewClientWithTimeout mirrors NewClient but lets the caller set the fallback
// I/O timeout. Context deadlines still override this when present.
func NewClientWithTimeout(connStr string, timeout time.Duration) (Client, error) {
	typ, addr, ok := strings.Cut(connStr, "://")
	if !ok {
		return nil, errors.Errorf("invalid connStr: %s", connStr)
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	switch typ {
	case "unix":
		return &UnixClient{
			socketPath:     addr,
			defaultTimeout: timeout,
		}, nil
	}
	return nil, errors.Errorf("invalid connStr: %s", connStr)
}

type Client interface {
	Close() error
	Dial(context.Context) error
	CollectStatsSummary(context.Context) (StatsSummary, error)
	Ping(context.Context) (PingResult, error)
	Info(context.Context) (InfoSummary, error)
}
