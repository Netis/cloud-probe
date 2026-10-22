package memfuse

import (
	"context"

	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"
)

type MemReader interface {
	// Available is MemAvailable of /proc/meminfo in MB, swap excluded.
	Available(ctx context.Context) (uint64, error)
	ProcessRSS(ctx context.Context, pid int) (uint64, error)
}

type gopsutilReader struct{}

func NewGopsutilReader() MemReader {
	return gopsutilReader{}
}

func (gopsutilReader) Available(ctx context.Context) (uint64, error) {
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "get machine memory")
	}
	return vm.Available >> 20, nil
}

func (gopsutilReader) ProcessRSS(ctx context.Context, pid int) (uint64, error) {
	p, err := process.NewProcessWithContext(ctx, int32(pid))
	if err != nil {
		return 0, errors.Wrap(err, "new process")
	}
	info, err := p.MemoryInfoWithContext(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "get process memory")
	}
	return info.RSS >> 20, nil
}
