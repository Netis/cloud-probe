package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/moby/moby/client"
	"github.com/moby/moby/client/pkg/versions"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <containerId>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s abc123def456\n", os.Args[0])
		os.Exit(1)
	}

	containerID := os.Args[1]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Negotiate the API version manually instead of relying on the client's
	// built-in negotiation. The moby client (v0.4.x) refuses to negotiate below
	// API 1.40, so against old daemons (e.g. Docker on CentOS 7 / older k8s
	// nodes, whose max API can be 1.39 or lower) it falls back to its own max
	// version (1.54) and the daemon rejects the request as "too new".
	//
	// The /_ping endpoint is unversioned and works against any daemon, so we
	// ping first to learn the daemon's advertised API version, then pin the
	// client to it (clamped to the client's max). This bypasses the 1.40 floor
	// and restores support for arbitrarily old daemons. DOCKER_API_VERSION (via
	// FromEnv) still takes precedence if explicitly set.
	apiVersion := negotiateAPIVersion(ctx)

	opts := []client.Opt{client.FromEnv}
	if apiVersion != "" {
		opts = append(opts, client.WithAPIVersion(apiVersion))
	}

	cli, err := client.New(opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Docker client: %v\n", err)
		os.Exit(1)
	}
	defer cli.Close()

	container, err := cli.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get container info: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(container.Container.State.Pid)
}

// negotiateAPIVersion pings the daemon (via the unversioned /_ping endpoint) and
// returns the API version to pin the client to: the daemon's advertised version,
// clamped to the client's maximum. It returns "" if the daemon is unreachable or
// advertises no version, in which case the caller leaves the client at its
// default and lets the real request surface any error.
func negotiateAPIVersion(ctx context.Context) string {
	// DOCKER_API_VERSION pins the version explicitly and takes precedence over
	// anything we negotiate, so skip the probe entirely when it is set.
	if os.Getenv(client.EnvOverrideAPIVersion) != "" {
		return ""
	}

	cli, err := client.New(client.FromEnv)
	if err != nil {
		return ""
	}
	defer cli.Close()

	ping, err := cli.Ping(ctx, client.PingOptions{})
	if err != nil || ping.APIVersion == "" {
		return ""
	}

	if versions.GreaterThan(ping.APIVersion, client.MaxAPIVersion) {
		return client.MaxAPIVersion
	}
	return ping.APIVersion
}
