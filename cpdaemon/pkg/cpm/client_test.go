package cpm

import (
	"context"
	"encoding/json"
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

// Zero values get the defaults; values the caller set are kept.
func TestClientConfig_SetDefaults(t *testing.T) {
	var zero ClientConfig
	zero.SetDefaults()
	assert.Equal(t, ClientConfig{
		Timeout:               15 * time.Second,
		DialTimeout:           5 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   5,
	}, zero)

	set := ClientConfig{
		Timeout:               time.Second,
		DialTimeout:           2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   6,
	}
	got := set
	got.SetDefaults()
	assert.Equal(t, set, got)
}

// CPM requires labels and networkInterfaces to be arrays, never null (RegisterRequest).
func TestHttpClient_RegisterSendsEmptyArrays(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	t.Cleanup(srv.Close)

	client, err := NewHttpClient(srv.URL, ClientConfig{})
	require.NoError(t, err)
	_, err = client.Register(context.Background(), RegisterRequest{})
	require.NoError(t, err)
	assert.Equal(t, []any{}, body["labels"])
	assert.Equal(t, []any{}, body["networkInterfaces"])
}

// CPM reports a failure either with a non-2xx status or with a body code of 400 or more.
func TestHttpClient_RegisterErrorResponses(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{"ok", http.StatusOK, `{"id":1}`, false},
		{"body_code_399", http.StatusOK, `{"code":399,"id":1}`, false},
		{"body_code_400", http.StatusOK, `{"code":400,"msg":"bad request"}`, true},
		{"status_299", 299, `{"id":1}`, false},
		{"status_300", http.StatusMultipleChoices, `{"id":1}`, true},
		{"status_500", http.StatusInternalServerError, `{}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)

			client, err := NewHttpClient(srv.URL, ClientConfig{})
			require.NoError(t, err)
			res, err := client.Register(context.Background(), RegisterRequest{})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, int64(1), res.Id)
		})
	}
}
