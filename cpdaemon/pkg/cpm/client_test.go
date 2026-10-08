package cpm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHttpClient_HonoursContextCancellation(t *testing.T) {
	// The server stalls well past the context deadline but well short of the client timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)

	client, err := NewHttpClient(srv.URL, ClientConfig{})
	require.NoError(t, err)

	calls := map[string]func(ctx context.Context) error{
		"register": func(ctx context.Context) error {
			_, err := client.Register(ctx, RegisterRequest{})
			return err
		},
		"sync strategy": func(ctx context.Context) error {
			_, err := client.SyncStrategy(ctx, 1, 0)
			return err
		},
		"sync metrics": func(ctx context.Context) error {
			return client.SyncMetrics(ctx, 1, SyncMetricsRequest{})
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			start := time.Now()
			err := call(ctx)

			require.Error(t, err)
			assert.True(t, errors.Is(err, context.DeadlineExceeded), "got %v", err)
			assert.Less(t, time.Since(start), time.Second)
		})
	}
}
