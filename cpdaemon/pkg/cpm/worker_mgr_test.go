package cpm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/testutils"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/worker"
)

func TestWorkerManager(t *testing.T) {
	require.NoError(t, os.MkdirAll("testdata/tmp", 0o755))

	mgr := NewWorkerManager(
		WorkerConfig{
			PidFile:        "testdata/tmp/cpm-worker.pid",
			ConfigFile:     "testdata/tmp/cpm-worker.json",
			Executable:     "../worker/fakeworker",
			ExecutionModel: "rtc",
			Control: worker.ControlConfig{
				Type: "unix",
				Unix: &worker.ControlUnixConfig{
					Path: "testdata/tmp/cpm-worker.sock",
				},
			},
			UpdatePolicy: UpdatePolicyRestart,
			Memory: MemoryConfig{
				Policy:         MemoryPolicyAutoNicBuffer,
				DefaultLimitMb: 256,
				Libpcap: LibpcapMemConfig{
					FixedBufferSizeMb: 4,
				},
			},
		},
		testTool{},
	)
	t.Cleanup(func() {
		mgr.Stop()
		os.RemoveAll("testdata/tmp")
	})

	var res SyncStrategyResponse
	require.NoError(t, testutils.LoadResultFromJSON("testdata/syncStrategy1.json", &res))

	{
		isAlive, err := mgr.IsAlive(context.Background())
		require.NoError(t, err)
		require.False(t, isAlive)

		pid := mgr.Pid()
		require.Zero(t, pid)
	}

	{
		_, err := mgr.Update(context.Background(), &res, "", []string{})
		require.NoError(t, err)

		isAlive, err := mgr.IsAlive(context.Background())
		require.NoError(t, err)
		require.True(t, isAlive)

		pid := mgr.Pid()
		require.NotZero(t, pid)
	}

	{
		_, err := mgr.CreateIfDead(context.Background(), &res, "", []string{})
		require.Error(t, err)
		assert.ErrorContains(t, err, "worker is still running")
	}

	{
		err := mgr.Stop()
		require.NoError(t, err)

		isAlive, err := mgr.IsAlive(context.Background())
		require.NoError(t, err)
		require.False(t, isAlive)

		pid := mgr.Pid()
		require.Zero(t, pid)
	}

	{
		_, err := mgr.CreateIfDead(context.Background(), &res, "", []string{})
		require.NoError(t, err)

		isAlive, err := mgr.IsAlive(context.Background())
		require.NoError(t, err)
		require.True(t, isAlive)

		pid := mgr.Pid()
		require.NotZero(t, pid)
	}

	{
		require.NoError(t, mgr.Kill())

		isAlive, err := mgr.IsAlive(context.Background())
		require.NoError(t, err)
		require.False(t, isAlive)
		require.Zero(t, mgr.Pid())

		_, err = mgr.CreateIfDead(context.Background(), &res, "", []string{})
		require.NoError(t, err, "a killed worker is gone, not still running")
	}
}

// The start gate is asked right before the worker starts, with the whole ring; a refusal leaves nothing behind.
func TestWorkerManager_startGate(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "cpm-worker.json")
	newMgr := func(t *testing.T) *WorkerManager {
		mgr := NewWorkerManager(
			WorkerConfig{
				PidFile:        filepath.Join(dir, "cpm-worker.pid"),
				ConfigFile:     cfgFile,
				Executable:     "../worker/fakeworker",
				ExecutionModel: "rtc",
				Control: worker.ControlConfig{
					Type: "unix",
					Unix: &worker.ControlUnixConfig{Path: filepath.Join(dir, "cpm-worker.sock")},
				},
				UpdatePolicy: UpdatePolicyRestart,
				Memory: MemoryConfig{
					Policy:         MemoryPolicyFixedNicBuffer,
					DefaultLimitMb: 256,
					Libpcap:        LibpcapMemConfig{FixedBufferSizeMb: 4},
				},
			},
			testTool{},
		)
		t.Cleanup(func() { mgr.Stop() })
		return mgr
	}
	var res SyncStrategyResponse
	require.NoError(t, testutils.LoadResultFromJSON("testdata/syncStrategy1.json", &res))
	ctx := context.Background()

	t.Run("refused", func(t *testing.T) {
		mgr := newMgr(t)
		var asked []RingAlloc
		mgr.SetStartGate(func(_ context.Context, alloc RingAlloc) bool {
			asked = append(asked, alloc)
			return false
		})
		_, err := mgr.Update(ctx, &res, "", nil)
		assert.ErrorIs(t, err, ErrStartRefused)
		assert.Equal(t, []RingAlloc{{NewCfgMb: 4, TotalCfgMb: 4, MemLimitMb: 256}}, asked)
		alive, err := mgr.IsAlive(ctx)
		require.NoError(t, err)
		assert.False(t, alive)
		_, err = os.Stat(cfgFile)
		assert.True(t, os.IsNotExist(err), "no config written")
		assert.Nil(t, mgr.current)
	})
	t.Run("allowed", func(t *testing.T) {
		mgr := newMgr(t)
		mgr.SetStartGate(func(context.Context, RingAlloc) bool { return true })
		_, err := mgr.Update(ctx, &res, "", nil)
		require.NoError(t, err)
		alive, err := mgr.IsAlive(ctx)
		require.NoError(t, err)
		assert.True(t, alive)
		require.Len(t, mgr.current, 1)
		assert.NotNil(t, mgr.current[0].Fingerprint)
		require.NoError(t, mgr.Stop())
		assert.Nil(t, mgr.current)
	})
}

// On a reload cpworker reuses the tasks it already runs by fingerprint, so only the others open a ring.
func TestWorkerManager_newRingCfgMb(t *testing.T) {
	task := func(fp string, mb uint64) *worker.TaskConfig {
		return &worker.TaskConfig{
			Fingerprint: lo.ToPtr(fp),
			Capturer: worker.CapturerConfig{
				Type:    worker.CapturerType_Libpcap,
				Libpcap: &worker.LibpcapConfig{BufferSizeMB: lo.ToPtr(mb)},
			},
		}
	}
	a, b, c := task("a", 10), task("b", 20), task("c", 40)
	b2 := task("b2", 20)
	other := &worker.TaskConfig{Fingerprint: lo.ToPtr("o"), Capturer: worker.CapturerConfig{Type: "pcap_file"}}
	noFp := task("", 5)
	noFp.Fingerprint = nil

	for _, tc := range []struct {
		name          string
		current, next []*worker.TaskConfig
		want          uint64
	}{
		{"nothing_running", nil, []*worker.TaskConfig{a, b, c}, 70},
		{"all_kept", []*worker.TaskConfig{a, b, c}, []*worker.TaskConfig{a, b, c}, 0},
		{"one_changed", []*worker.TaskConfig{a, b, c}, []*worker.TaskConfig{a, b2, c}, 20},
		{"one_added", []*worker.TaskConfig{a, b}, []*worker.TaskConfig{a, b, c}, 40},
		{"one_removed", []*worker.TaskConfig{a, b, c}, []*worker.TaskConfig{a, b}, 0},
		{"non_libpcap_counts_nothing", nil, []*worker.TaskConfig{other}, 0},
		{"no_fingerprint_is_new", []*worker.TaskConfig{a}, []*worker.TaskConfig{a, noFp}, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, newRingCfgMb(tc.current, tc.next))
		})
	}
}

// auto_nic_buffer splits the memory limit evenly over the tasks; the limit from CPM replaces
// the configured default only when it is set and positive.
func TestWorkerManager_taskBufferSize(t *testing.T) {
	twoNics := &SyncStrategyResponse{Strategy: []StrategyEntry{{InterfaceNames: []string{"eth0", "eth1"}}}}
	withLimit := func(mb int64) *SyncStrategyResponse {
		r := *twoNics
		r.MemLimit = &mb
		return &r
	}
	cases := []struct {
		name    string
		policy  string
		res     *SyncStrategyResponse
		want    uint64
		wantErr bool
	}{
		{"fixed", MemoryPolicyFixedNicBuffer, twoNics, 4, false},
		{"auto_default_limit", MemoryPolicyAutoNicBuffer, twoNics, 128, false},
		{"auto_cpm_limit", MemoryPolicyAutoNicBuffer, withLimit(1000), 500, false},
		{"auto_cpm_limit_0_uses_default", MemoryPolicyAutoNicBuffer, withLimit(0), 128, false},
		{"auto_one_mb_per_task", MemoryPolicyAutoNicBuffer, withLimit(2), 1, false},
		{"auto_limit_below_task_count", MemoryPolicyAutoNicBuffer, withLimit(1), 0, true},
		{"auto_no_tasks", MemoryPolicyAutoNicBuffer, &SyncStrategyResponse{}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := NewWorkerManager(WorkerConfig{Memory: MemoryConfig{
				Policy:         tc.policy,
				DefaultLimitMb: 256,
				Libpcap:        LibpcapMemConfig{FixedBufferSizeMb: 4},
			}}, testTool{})
			got, err := mgr.getTaskBufferSizeMb(tc.res, nil)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// NicBufferTotalMb is the configured buffer of all tasks, without the fuse's ×2 estimate.
func TestWorkerManager_NicBufferTotalMb(t *testing.T) {
	twoNics := &SyncStrategyResponse{Strategy: []StrategyEntry{{InterfaceNames: []string{"eth0", "eth1"}}}}
	limit := int64(2048)
	oneNicLimited := &SyncStrategyResponse{MemLimit: &limit, Strategy: []StrategyEntry{{InterfaceNames: []string{"eth0"}}}}
	cases := []struct {
		name   string
		policy string
		res    *SyncStrategyResponse
		want   uint64
	}{
		{"fixed", MemoryPolicyFixedNicBuffer, twoNics, 8},
		{"fixed_no_tasks", MemoryPolicyFixedNicBuffer, &SyncStrategyResponse{}, 0},
		{"auto_default_limit", MemoryPolicyAutoNicBuffer, twoNics, 256},
		{"auto_cpm_limit", MemoryPolicyAutoNicBuffer, oneNicLimited, 2048},
		{"auto_no_tasks", MemoryPolicyAutoNicBuffer, &SyncStrategyResponse{}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := NewWorkerManager(WorkerConfig{Memory: MemoryConfig{
				Policy:         tc.policy,
				DefaultLimitMb: 256,
				Libpcap:        LibpcapMemConfig{FixedBufferSizeMb: 4},
			}}, testTool{})
			got, err := mgr.NicBufferTotalMb(tc.res, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// Only the pipeline execution model gets a pipeline section: the memory left after the
// libpcap buffers, but at least MinBufferSizeMb. cpu_affinity is passed through when configured.
func TestWorkerManager_newWorkerConfig(t *testing.T) {
	tasks := []*worker.TaskConfig{{Capturer: worker.CapturerConfig{
		Type:    worker.CapturerType_Libpcap,
		Libpcap: &worker.LibpcapConfig{BufferSizeMB: lo.ToPtr[uint64](100)},
	}}}

	rtc := NewWorkerManager(WorkerConfig{ExecutionModel: worker.EXECUTION_MODEL_RTC}, testTool{})
	cfg := rtc.newWorkerConfig(tasks, &SyncStrategyResponse{})
	assert.Nil(t, cfg.Pipeline)
	assert.Nil(t, cfg.CpuAffinity)

	cases := []struct {
		name     string
		cpmLimit *int64
		want     uint64
	}{
		{"default_limit", nil, 1024 - 100},
		{"cpm_limit", lo.ToPtr[int64](2048), 2048 - 100},
		{"cpm_limit_0_uses_default", lo.ToPtr[int64](0), 1024 - 100},
		{"left_below_minimum", lo.ToPtr[int64](150), 64},
		{"nothing_left", lo.ToPtr[int64](80), 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pipeline := NewWorkerManager(WorkerConfig{
				ExecutionModel: worker.EXECUTION_MODEL_PIPELINE,
				CpuAffinity:    "1-3",
				Pipeline:       PipelineConfig{MinBufferSizeMb: 64},
				Memory:         MemoryConfig{DefaultLimitMb: 1024},
			}, testTool{})
			cfg := pipeline.newWorkerConfig(tasks, &SyncStrategyResponse{MemLimit: tc.cpmLimit})
			require.NotNil(t, cfg.Pipeline)
			assert.Equal(t, tc.want, cfg.Pipeline.BufferSizeMB)
			assert.Equal(t, lo.ToPtr("1-3"), cfg.CpuAffinity)
		})
	}
}

// The worker binds its control socket itself, so its directory must exist before the start.
func TestWorkerManager_createsControlSocketDir(t *testing.T) {
	sockDir := filepath.Join(t.TempDir(), "run")
	mgr := NewWorkerManager(
		WorkerConfig{
			PidFile:        filepath.Join(t.TempDir(), "w.pid"),
			ConfigFile:     filepath.Join(t.TempDir(), "w.json"),
			Executable:     "../worker/fakeworker",
			ExecutionModel: worker.EXECUTION_MODEL_RTC,
			Control: worker.ControlConfig{
				Type: "unix",
				Unix: &worker.ControlUnixConfig{Path: filepath.Join(sockDir, "w.sock")},
			},
			UpdatePolicy: UpdatePolicyRestart,
			Memory:       MemoryConfig{Policy: MemoryPolicyAutoNicBuffer, DefaultLimitMb: 256},
		},
		testTool{},
	)
	t.Cleanup(func() { mgr.Stop() })

	var res SyncStrategyResponse
	require.NoError(t, testutils.LoadResultFromJSON("testdata/syncStrategy1.json", &res))
	_, err := mgr.CreateIfDead(context.Background(), &res, "", []string{})
	require.NoError(t, err)
	assert.DirExists(t, sockDir)
}
