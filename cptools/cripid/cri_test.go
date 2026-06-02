package main

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestParsePIDFromInfo(t *testing.T) {
	tests := []struct {
		name    string
		info    map[string]string
		want    int
		wantErr bool
	}{
		{
			name: "containerd shape",
			info: map[string]string{"info": `{"sandboxID":"abc","pid":4242,"runtimeType":"io.containerd.runc.v2"}`},
			want: 4242,
		},
		{
			name: "crio shape with extra keys",
			info: map[string]string{
				"sandboxID": `"def"`,
				"info":      `{"pid":777,"privileged":false}`,
			},
			want: 777,
		},
		{
			name:    "missing pid",
			info:    map[string]string{"info": `{"sandboxID":"abc"}`},
			wantErr: true,
		},
		{
			name:    "zero pid is rejected",
			info:    map[string]string{"info": `{"pid":0}`},
			wantErr: true,
		},
		{
			name:    "malformed json is skipped",
			info:    map[string]string{"info": `not json`},
			wantErr: true,
		},
		{
			name:    "empty info",
			info:    map[string]string{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePIDFromInfo(tt.info)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got pid %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestEndpoints(t *testing.T) {
	t.Run("env override wins", func(t *testing.T) {
		t.Setenv("CONTAINER_RUNTIME_ENDPOINT", "unix:///tmp/custom.sock")
		got := endpoints()
		if len(got) != 1 || got[0] != "unix:///tmp/custom.sock" {
			t.Fatalf("got %v, want [unix:///tmp/custom.sock]", got)
		}
	})

	t.Run("env override is trimmed", func(t *testing.T) {
		t.Setenv("CONTAINER_RUNTIME_ENDPOINT", "  unix:///tmp/custom.sock  ")
		got := endpoints()
		if len(got) != 1 || got[0] != "unix:///tmp/custom.sock" {
			t.Fatalf("got %v, want [unix:///tmp/custom.sock]", got)
		}
	})

	t.Run("defaults when env unset", func(t *testing.T) {
		t.Setenv("CONTAINER_RUNTIME_ENDPOINT", "")
		got := endpoints()
		want := []string{
			"unix:///run/containerd/containerd.sock",
			"unix:///run/crio/crio.sock",
			"unix:///var/run/cri-dockerd.sock",
		}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("index %d: got %q, want %q", i, got[i], want[i])
			}
		}
	})
}

type fakeRuntimeServer struct {
	runtimeapi.UnimplementedRuntimeServiceServer
	info    map[string]string
	callErr error
}

func (f *fakeRuntimeServer) ContainerStatus(ctx context.Context, req *runtimeapi.ContainerStatusRequest) (*runtimeapi.ContainerStatusResponse, error) {
	if f.callErr != nil {
		return nil, f.callErr
	}
	return &runtimeapi.ContainerStatusResponse{Info: f.info}, nil
}

func startFakeCRI(t *testing.T, srv *fakeRuntimeServer) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "cri.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := grpc.NewServer()
	runtimeapi.RegisterRuntimeServiceServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return "unix://" + sock
}

func TestGetContainerPID(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ep := startFakeCRI(t, &fakeRuntimeServer{
			info: map[string]string{"info": `{"pid":4242}`},
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pid, err := getContainerPID(ctx, ep, "abc123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pid != 4242 {
			t.Fatalf("got %d, want 4242", pid)
		}
	})

	t.Run("info without pid errors", func(t *testing.T) {
		ep := startFakeCRI(t, &fakeRuntimeServer{
			info: map[string]string{"info": `{"sandboxID":"x"}`},
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := getContainerPID(ctx, ep, "abc123"); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("rpc error propagates", func(t *testing.T) {
		ep := startFakeCRI(t, &fakeRuntimeServer{
			callErr: status.Error(codes.NotFound, "container not found"),
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := getContainerPID(ctx, ep, "abc123"); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestResolve(t *testing.T) {
	t.Run("returns pid from endpoint", func(t *testing.T) {
		ep := startFakeCRI(t, &fakeRuntimeServer{info: map[string]string{"info": `{"pid":1234}`}})
		t.Setenv("CONTAINER_RUNTIME_ENDPOINT", ep)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pid, err := resolve(ctx, "abc123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pid != 1234 {
			t.Fatalf("got %d, want 1234", pid)
		}
	})

	t.Run("missing socket yields no-endpoint error", func(t *testing.T) {
		t.Setenv("CONTAINER_RUNTIME_ENDPOINT", "unix:///nonexistent/cri.sock")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := resolve(ctx, "abc123"); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
