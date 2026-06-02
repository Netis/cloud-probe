package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <containerId>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s abc123def456\n", os.Args[0])
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pid, err := resolve(ctx, os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get container info: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(pid)
}

// resolve tries each candidate CRI endpoint in order and returns the first
// successful host-PID lookup. Unix endpoints whose socket file does not exist
// are skipped so a missing runtime does not stall the dial until the deadline.
func resolve(ctx context.Context, containerID string) (int, error) {
	var lastErr error
	for _, ep := range endpoints() {
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}
		exists, err := socketExists(ep)
		if err != nil {
			lastErr = err
			continue
		}
		if !exists {
			continue
		}
		pid, err := getContainerPID(ctx, ep, containerID)
		if err != nil {
			lastErr = err
			continue
		}
		return pid, nil
	}
	if lastErr != nil {
		return 0, lastErr
	}
	return 0, errors.New("no CRI runtime endpoint available")
}

// socketExists reports whether a unix:// endpoint's socket file is present.
// Non-unix endpoints (e.g. an explicit tcp override) return true so the dial
// attempt decides. A not-exist result is reported as (false, nil) so the
// endpoint is skipped; any other stat error (e.g. permission denied) is
// returned so it surfaces instead of masquerading as "no runtime".
func socketExists(endpoint string) (bool, error) {
	path, ok := strings.CutPrefix(endpoint, "unix://")
	if !ok {
		return true, nil
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	return true, nil
}
