package worker

import (
	"context"
	"os"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
)

func TestWorker(t *testing.T) {
	require.NoError(t, os.MkdirAll("testdata/tmp", 0o755))

	cfg := ExecConfig{
		Executable: "./fakeworker",
		ConfigFile: "testdata/tmp/test-tasks.json",
		Control: ControlConfig{
			Type: "unix",
			Unix: &ControlUnixConfig{
				Path: "testdata/tmp/test.sock",
			},
		},
		Tasks: []TaskConfig{
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
		err := w.Start(context.Background())
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
