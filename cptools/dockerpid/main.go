package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/docker/docker/client"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <containerId>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s abc123def456\n", os.Args[0])
		os.Exit(1)
	}

	containerID := os.Args[1]

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Docker client: %v\n", err)
		os.Exit(1)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	container, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get container info: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(container.State.Pid)
}
