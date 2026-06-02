package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// parsePIDFromInfo extracts the host PID from a CRI ContainerStatus verbose
// Info map. The map's values are runtime-specific JSON blobs; containerd and
// CRI-O both expose the host PID as a top-level "pid" field inside the value
// keyed "info". We scan every value rather than hardcoding the key so the same
// code works across runtimes.
func parsePIDFromInfo(info map[string]string) (int, error) {
	for _, v := range info {
		var ci struct {
			Pid int `json:"pid"`
		}
		if err := json.Unmarshal([]byte(v), &ci); err == nil && ci.Pid > 0 {
			return ci.Pid, nil
		}
	}
	return 0, errors.New("no pid found in container info")
}

const envRuntimeEndpoint = "CONTAINER_RUNTIME_ENDPOINT"

// defaultRuntimeEndpoints mirrors crictl's standard default list. On target
// nodes /run resolves to /var/run (symlink), so DaemonSet hostPath mounts at
// /var/run/... are reachable through these paths.
var defaultRuntimeEndpoints = []string{
	"unix:///run/containerd/containerd.sock",
	"unix:///run/crio/crio.sock",
	"unix:///var/run/cri-dockerd.sock",
}

// endpoints returns the CRI endpoints to try, in priority order. An explicit
// CONTAINER_RUNTIME_ENDPOINT takes precedence over the defaults.
func endpoints() []string {
	if ep := strings.TrimSpace(os.Getenv(envRuntimeEndpoint)); ep != "" {
		return []string{ep}
	}
	return defaultRuntimeEndpoints
}

// getContainerPID dials a single CRI endpoint and returns the container's host
// PID via the v1 ContainerStatus RPC. The endpoint is a gRPC target such as
// "unix:///run/containerd/containerd.sock"; the connection is lazy, so the
// actual connect happens during the RPC and is bounded by ctx.
func getContainerPID(ctx context.Context, endpoint, containerID string) (int, error) {
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return 0, fmt.Errorf("dial %s: %w", endpoint, err)
	}
	defer conn.Close()

	client := runtimeapi.NewRuntimeServiceClient(conn)
	resp, err := client.ContainerStatus(ctx, &runtimeapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	})
	if err != nil {
		return 0, fmt.Errorf("ContainerStatus via %s: %w", endpoint, err)
	}
	return parsePIDFromInfo(resp.Info)
}
