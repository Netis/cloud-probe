package worker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
)

func TestWorker(t *testing.T) {
	require.NoError(t, os.MkdirAll("testdata/tmp", 0o755))

	cfg := ExecConfig{
		Executable: "./fakeworker",
		ConfigFile: "testdata/tmp/test-tasks.json",
	}

	wCfg := &Config{
		LogLevel: "info",
		Control: ControlConfig{
			Type: "unix",
			Unix: &ControlUnixConfig{
				Path: "testdata/tmp/test.sock",
			},
		},
		Tasks: []*TaskConfig{
			{
				Capturer: CapturerConfig{
					Type: "libpcap",
					Libpcap: &LibpcapConfig{
						Interface:    "eth0",
						Snaplen:      lo.ToPtr(65535),
						BufferSizeMB: lo.ToPtr[uint64](256),
						TimeoutMs:    lo.ToPtr(0),
					},
				},
				Outputs: []OutputConfig{
					{
						Type: "zmq",
						Zmq: &ZmqOutputConfig{
							Host: "127.0.0.1",
							Port: 5555,
						},
					},
				},
			},
		},
	}
	w, err := NewWorker("test", cfg)
	require.NoError(t, err)

	{
		isAlive, err := w.IsAlive(context.Background())
		require.NoError(t, err)
		require.False(t, isAlive)

		pid := w.Pid()
		require.Zero(t, pid)
	}

	{
		err := w.Start(context.Background(), wCfg)
		require.NoError(t, err)

		err = w.UpdateResLimit(ResLimit{})
		require.NoError(t, err)

		isAlive, err := w.IsAlive(context.Background())
		require.NoError(t, err)
		require.True(t, isAlive)

		pid := w.Pid()
		require.NotZero(t, pid)
	}

	{
		err := w.Stop()
		require.NoError(t, err)

		isAlive, err := w.IsAlive(context.Background())
		require.NoError(t, err)
		require.False(t, isAlive)

		pid := w.Pid()
		require.Zero(t, pid)
	}
}

// Stop must not return before the exit cleanup has run: a restart reuses the
// same pid file and cgroup right after Stop returns.
func TestWorker_StopReturnsAfterCleanup(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "worker.pid")
	w, err := NewWorker("test", ExecConfig{
		Executable: "./fakeworker",
		ConfigFile: filepath.Join(dir, "tasks.json"),
		PidFile:    pidFile,
	})
	require.NoError(t, err)

	wCfg := &Config{LogLevel: "info", Control: ControlConfig{Type: "unix"}}
	for i := 0; i < 100; i++ {
		require.NoError(t, w.Start(context.Background(), wCfg))
		require.Eventually(t, func() bool {
			_, err := os.Stat(pidFile)
			return err == nil
		}, 5*time.Second, time.Millisecond, "round %d: pid file not created", i)

		require.NoError(t, w.Stop())

		require.Zero(t, w.Pid(), "round %d: pid still set after Stop", i)
		_, err := os.Stat(pidFile)
		require.True(t, os.IsNotExist(err), "round %d: pid file still present after Stop", i)
	}
}
