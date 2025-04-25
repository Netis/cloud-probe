package cpm

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/testutils"
)

func TestWorkerManager(t *testing.T) {
	require.NoError(t, os.MkdirAll("testdata/tmp", 0o755))

	mgr := NewWorkerManager(
		WorkerConfig{
			Executable: "../worker/fakeworker",
			UnixSocket: "testdata/tmp/test.sock",
			ConfigFile: "testdata/tmp/test-tasks.json",
		},
		testTool{},
	)
	t.Cleanup(func() {
		mgr.Stop()
	})

	var res SyncStrategyResponse
	require.NoError(t, testutils.LoadResultFromJSON("testdata/syncStrategy1.json", &res))

	{
		isAlive, err := mgr.IsAlive(context.Background())
		require.NoError(t, err)
		require.False(t, isAlive)

		pid, ok := mgr.Pid()
		require.False(t, ok)
		require.Zero(t, pid)
	}

	{
		err := mgr.Update(context.Background(), &res, "", []string{})
		require.NoError(t, err)

		isAlive, err := mgr.IsAlive(context.Background())
		require.NoError(t, err)
		require.True(t, isAlive)

		pid, ok := mgr.Pid()
		require.True(t, ok)
		require.NotZero(t, pid)

		err = mgr.CreateIfDead(context.Background(), &res, "", []string{})
		require.Error(t, err)
		assert.ErrorContains(t, err, "worker is still running")
	}

	{
		err := mgr.Stop()
		require.NoError(t, err)

		isAlive, err := mgr.IsAlive(context.Background())
		require.NoError(t, err)
		require.False(t, isAlive)

		pid, ok := mgr.Pid()
		require.False(t, ok)
		require.Zero(t, pid)
	}

	{
		err := mgr.CreateIfDead(context.Background(), &res, "", []string{})
		require.NoError(t, err)

		isAlive, err := mgr.IsAlive(context.Background())
		require.NoError(t, err)
		require.True(t, isAlive)

		pid, ok := mgr.Pid()
		require.True(t, ok)
		require.NotZero(t, pid)
	}
}
