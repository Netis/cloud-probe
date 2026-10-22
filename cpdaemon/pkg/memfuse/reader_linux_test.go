package memfuse

import (
	"context"
	"os"
	"testing"

	"github.com/shirou/gopsutil/v4/mem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGopsutilReader(t *testing.T) {
	ctx := context.Background()
	r := NewGopsutilReader()

	vm, err := mem.VirtualMemoryWithContext(ctx)
	require.NoError(t, err)
	avail, err := r.Available(ctx)
	require.NoError(t, err)
	assert.Greater(t, avail, uint64(0))
	assert.LessOrEqual(t, avail, vm.Total>>20)

	rss, err := r.ProcessRSS(ctx, os.Getpid())
	require.NoError(t, err)
	assert.Greater(t, rss, uint64(0))
}
