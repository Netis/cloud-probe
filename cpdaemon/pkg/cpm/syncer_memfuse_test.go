package cpm

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/memfuse"
)

type fakeMemReader struct {
	avail uint64
	err   error
	rss   uint64
	reads int
}

func (r *fakeMemReader) Available(ctx context.Context) (uint64, error) {
	r.reads++
	return r.avail, r.err
}

func (r *fakeMemReader) ProcessRSS(ctx context.Context, pid int) (uint64, error) {
	return r.rss, nil
}

type fuseFixture struct {
	s         *Syncer
	workerMgr *testWorkerManagerRecoder
	reader    *fakeMemReader
	reports   []SyncMetricsRequest
	// callsAtReport is the worker manager's call log at each report.
	callsAtReport [][]string
	reportErr     error
}

// newFuseFixture builds a registered syncer whose fuse needs 2×nicMb+256 MB available to start.
func newFuseFixture(t *testing.T, nicMb, avail uint64) *fuseFixture {
	t.Helper()
	f := &fuseFixture{
		workerMgr: &testWorkerManagerRecoder{nicBufferTotalMb: nicMb},
		reader:    &fakeMemReader{avail: avail, rss: 40},
	}
	client := &testClient{syncMetricsFn: func(ctx context.Context, daemonId int64, req SyncMetricsRequest) error {
		f.reports = append(f.reports, req)
		f.callsAtReport = append(f.callsAtReport, slices.Clone(f.workerMgr.calls))
		return f.reportErr
	}}
	f.s = newTestSyncer(t, client, f.workerMgr, SyncerConfig{MemFuse: memfuse.Config{
		CheckInterval:  5 * time.Second,
		FailThreshold:  3,
		MinAvailableMb: 256,
	}})
	f.s.memReader = f.reader
	f.s.regResp = &RegisterResponse{Id: 1}
	return f
}

func fuseStrategy(version int32, enabled, fused bool) *SyncStrategyResult {
	return &SyncStrategyResult{Changed: true, Response: &SyncStrategyResponse{
		DaemonId:       1,
		Version:        version,
		MemFuseEnabled: enabled,
		MemFused:       fused,
		Strategy:       []StrategyEntry{{InterfaceNames: []string{"eth0"}}},
	}}
}

var unchanged = &SyncStrategyResult{Changed: false}

func (f *fuseFixture) apply(t *testing.T, res *SyncStrategyResult) {
	t.Helper()
	require.NoError(t, f.s.applyStrategy(context.Background(), res))
}

func (f *fuseFixture) count(call string) int {
	n := 0
	for _, c := range f.workerMgr.Calls() {
		if c == call {
			n++
		}
	}
	return n
}

func (f *fuseFixture) lastReport(t *testing.T) SyncMetricsRequest {
	t.Helper()
	require.NotEmpty(t, f.reports)
	return f.reports[len(f.reports)-1]
}

// A failed startup check before a new strategy stops the running worker, reports at once and keeps the version.
func TestSyncerMemFuse_startupCheckBlocksUpdate(t *testing.T) {
	f := newFuseFixture(t, 100, 2*100+256)
	f.apply(t, fuseStrategy(1, true, false))
	require.Equal(t, 1, f.count("Update"))
	require.Equal(t, memfuse.Armed, f.s.fuse.State())

	f.workerMgr.newRingCfgMb = 100 // every task changes
	f.reader.avail = 2*100 + 256 - 1
	res := fuseStrategy(2, true, false)
	f.apply(t, res)
	assert.Equal(t, 1, f.count("Update"), "the new strategy is not applied")
	assert.Equal(t, 1, f.count("Kill"))
	assert.Same(t, res.Response, f.s.syncResp, "the version advances")

	rep := f.lastReport(t)
	assert.Nil(t, rep.Pid)
	assert.Nil(t, rep.Metrics)
	require.NotNil(t, rep.MemFuse)
	assert.Equal(t, "fused", rep.MemFuse.State)
	assert.Equal(t, "startup", *rep.MemFuse.Reason)
	assert.Equal(t, uint64(200), rep.MemFuse.NicBufferMb)
	assert.Equal(t, uint64(455), *rep.MemFuse.MemAvailableMb)
	assert.Equal(t, uint64(40), *rep.MemFuse.WorkerRssMb, "the worker was running at the check")
	assert.Equal(t, uint64(512), *rep.MemFuse.MemLimitMb)
	assert.Equal(t, memfuse.Fused, f.s.fuse.State(), "the report got a 200")
}

// The first strategy after a start: the worker is not running, so the report carries an RSS of 0, not a missing field.
func TestSyncerMemFuse_startupCheckBeforeFirstStart(t *testing.T) {
	f := newFuseFixture(t, 2048, 335)
	f.apply(t, fuseStrategy(1, true, false))
	assert.Zero(t, f.count("Update"))
	rep := f.lastReport(t)
	require.NotNil(t, rep.MemFuse.WorkerRssMb)
	assert.Equal(t, uint64(0), *rep.MemFuse.WorkerRssMb)
	assert.Equal(t, uint64(4096), rep.MemFuse.NicBufferMb)
}

func TestSyncerMemFuse_startupCheckBlocksCreateIfDead(t *testing.T) {
	f := newFuseFixture(t, 100, 1000)
	f.apply(t, fuseStrategy(1, true, false))
	f.workerMgr.kill()

	f.reader.avail = 100
	f.apply(t, unchanged)
	assert.Zero(t, f.count("CreateIfDead"))
	assert.Equal(t, memfuse.Fused, f.s.fuse.State())
	assert.Equal(t, "startup", *f.lastReport(t).MemFuse.Reason)
}

// A worker the kernel killed still has a pid until it is stopped; the startup check must not log it as running.
func TestSyncerMemFuse_startupCheckLogsNoDeadWorkerPid(t *testing.T) {
	f := newFuseFixture(t, 100, 1000)
	f.apply(t, fuseStrategy(1, true, false))
	f.workerMgr.kill()
	require.NotZero(t, f.workerMgr.Pid())

	f.reader.avail = 100
	f.apply(t, unchanged)
	var line string
	for _, l := range f.lastReport(t).Logs {
		if strings.Contains(l.Details, "startup check failed") {
			line = l.Details
		}
	}
	require.NotEmpty(t, line)
	assert.NotContains(t, line, "worker_pid")
	assert.Contains(t, line, "worker_rss_mb=0")
}

func TestSyncerMemFuse_startupCheckBlocksInstanceUpdate(t *testing.T) {
	f := newFuseFixture(t, 100, 1000)
	f.s.tool = testTool{kvmInstances: []string{"vm1"}}
	res := fuseStrategy(1, true, false)
	res.Response.Strategy = []StrategyEntry{{InstanceNames: []string{"vm1", "vm2"}}}
	f.apply(t, res)
	require.Equal(t, 1, f.count("Update"))

	f.s.tool = testTool{kvmInstances: []string{"vm1", "vm2"}}
	f.workerMgr.newRingCfgMb = 50 // the task of the new instance
	f.reader.avail = 100
	f.apply(t, unchanged)
	assert.Equal(t, 1, f.count("Update"), "the instance change is not applied")
	assert.Equal(t, 1, f.count("Kill"))
	assert.Equal(t, memfuse.Fused, f.s.fuse.State())
}

// N consecutive hits: tripped, then Kill, then an immediate report.
func TestSyncerMemFuse_runtimeTrip(t *testing.T) {
	f := newFuseFixture(t, 8, 1000)
	f.apply(t, fuseStrategy(1, true, false))

	f.reader.avail = 255
	var stateAtReport memfuse.State
	f.s.client.(*testClient).syncMetricsFn = func(ctx context.Context, daemonId int64, req SyncMetricsRequest) error {
		stateAtReport = f.s.fuse.State()
		f.reports = append(f.reports, req)
		f.callsAtReport = append(f.callsAtReport, slices.Clone(f.workerMgr.calls))
		return nil
	}
	ctx := context.Background()
	f.s.onFuseTick(ctx)
	f.s.onFuseTick(ctx)
	assert.Empty(t, f.reports)
	assert.Zero(t, f.count("Kill"))
	f.s.onFuseTick(ctx)

	require.Len(t, f.reports, 1)
	assert.Equal(t, memfuse.Tripped, stateAtReport)
	assert.Contains(t, f.callsAtReport[0], "Kill", "stopped before the report")
	rep := f.reports[0]
	assert.Nil(t, rep.Pid)
	assert.Equal(t, "runtime", *rep.MemFuse.Reason)
	assert.Equal(t, uint64(255), *rep.MemFuse.MemAvailableMb)
	assert.Equal(t, uint64(40), *rep.MemFuse.WorkerRssMb)
	assert.Equal(t, memfuse.Fused, f.s.fuse.State())
}

func TestSyncerMemFuse_runtimeReadFailureDoesNotCount(t *testing.T) {
	f := newFuseFixture(t, 8, 1000)
	f.apply(t, fuseStrategy(1, true, false))
	ctx := context.Background()

	f.reader.avail = 100
	f.s.onFuseTick(ctx)
	f.s.onFuseTick(ctx)
	f.reader.err = errors.New("no meminfo")
	f.s.onFuseTick(ctx)
	assert.Equal(t, memfuse.Armed, f.s.fuse.State())
	f.reader.err = nil
	f.s.onFuseTick(ctx)
	assert.Equal(t, memfuse.Fused, f.s.fuse.State(), "the third hit after the failed read trips")
}

func TestSyncerMemFuse_runtimeCheckNeedsRunningWorker(t *testing.T) {
	f := newFuseFixture(t, 8, 1000)
	f.apply(t, fuseStrategy(1, true, false))
	f.workerMgr.kill()
	f.reader.avail = 100
	for range 5 {
		f.s.onFuseTick(context.Background())
	}
	assert.Equal(t, memfuse.Armed, f.s.fuse.State())
}

// Until CPM acknowledges, the fuse stays tripped, keeps reporting the same round and ignores strategies.
func TestSyncerMemFuse_reportFailureStaysTripped(t *testing.T) {
	f := newFuseFixture(t, 100, 100)
	f.reportErr = errors.New("cpm down")
	f.apply(t, fuseStrategy(1, true, false))
	require.Equal(t, memfuse.Tripped, f.s.fuse.State())
	first := *f.lastReport(t).MemFuse.FusedTimestamp

	res := fuseStrategy(2, true, false)
	f.apply(t, res)
	assert.Zero(t, f.count("Update"))
	assert.Same(t, res.Response, f.s.syncResp)
	assert.Equal(t, memfuse.Tripped, f.s.fuse.State(), "memFused=false while tripped is not a clear")

	f.s.syncMetric(context.Background())
	rep := f.lastReport(t)
	assert.Equal(t, "fused", rep.MemFuse.State)
	assert.Equal(t, first, *rep.MemFuse.FusedTimestamp)

	f.reportErr = nil
	f.s.syncMetric(context.Background())
	assert.Equal(t, memfuse.Fused, f.s.fuse.State())
}

func TestSyncerMemFuse_fusedShortCircuitsCreateIfDead(t *testing.T) {
	f := newFuseFixture(t, 100, 100)
	f.apply(t, fuseStrategy(1, true, false))
	f.apply(t, fuseStrategy(2, true, true))
	require.Equal(t, memfuse.Fused, f.s.fuse.State())

	f.reader.avail = 100000
	f.apply(t, unchanged)
	assert.Zero(t, f.count("CreateIfDead"))
	assert.Zero(t, f.count("Update"))
}

// A strategy change that keeps every task opens no ring, so nothing is checked even with no memory at all.
func TestSyncerMemFuse_unchangedTasksSkipStartupCheck(t *testing.T) {
	f := newFuseFixture(t, 1000, 100000)
	f.apply(t, fuseStrategy(1, true, false))
	require.Equal(t, 1, f.count("Update"))
	reads := f.reader.reads

	f.workerMgr.newRingCfgMb = 0
	f.reader.avail = 0
	res := fuseStrategy(2, true, false)
	f.apply(t, res)
	assert.Equal(t, 2, f.count("Update"))
	assert.Zero(t, f.count("Kill"))
	assert.Equal(t, reads, f.reader.reads, "no reading taken")
	assert.Equal(t, memfuse.Armed, f.s.fuse.State())
	assert.Same(t, res.Response, f.s.syncResp)
}

// While the worker runs, only the ring of the tasks that change is demanded on top of what is resident; the report
// still carries the whole ring.
func TestSyncerMemFuse_startupCheckDemandsOnlyTheNewRing(t *testing.T) {
	newFixture := func(t *testing.T) *fuseFixture {
		f := newFuseFixture(t, 1000, 100000)
		f.apply(t, fuseStrategy(1, true, false))
		require.Equal(t, 1, f.count("Update"))
		f.workerMgr.newRingCfgMb = 100
		return f
	}
	t.Run("passes", func(t *testing.T) {
		f := newFixture(t)
		f.reader.avail = 2*100 + 256
		f.apply(t, fuseStrategy(2, true, false))
		assert.Equal(t, 2, f.count("Update"))
		assert.Equal(t, memfuse.Armed, f.s.fuse.State())
	})
	t.Run("trips", func(t *testing.T) {
		f := newFixture(t)
		f.reader.avail = 2*100 + 256 - 1
		f.apply(t, fuseStrategy(2, true, false))
		assert.Equal(t, 1, f.count("Update"))
		assert.Equal(t, 1, f.count("Kill"))
		rep := f.lastReport(t)
		assert.Equal(t, "fused", rep.MemFuse.State)
		assert.Equal(t, uint64(2000), rep.MemFuse.NicBufferMb)
		var line string
		for _, l := range rep.Logs {
			if strings.Contains(l.Details, "startup check failed") {
				line = l.Details
			}
		}
		require.NotEmpty(t, line)
		assert.Contains(t, line, "new_nic_buffer_mb=200")
		assert.Contains(t, line, "nic_buffer_mb=2000")
		assert.Contains(t, line, "worker_pid=")
	})
}

// The startup check refuses on its own while tripped or fused, without reading memory or starting a new round.
func TestSyncerMemFuse_startupCheckRefusesWhenFused(t *testing.T) {
	t.Run("tripped", func(t *testing.T) {
		f := newFuseFixture(t, 100, 100)
		f.reportErr = errors.New("cpm down")
		f.apply(t, fuseStrategy(1, true, false))
		require.Equal(t, memfuse.Tripped, f.s.fuse.State())
		f.assertStartupCheckRefuses(t)
	})
	t.Run("fused", func(t *testing.T) {
		f := newFuseFixture(t, 100, 1000)
		f.apply(t, fuseStrategy(1, true, true))
		require.Equal(t, memfuse.Fused, f.s.fuse.State())
		f.assertStartupCheckRefuses(t)
	})
}

func (f *fuseFixture) assertStartupCheckRefuses(t *testing.T) {
	t.Helper()
	f.reader.avail = 100000
	reads, reports, stops := f.reader.reads, len(f.reports), f.count("Kill")
	assert.False(t, f.s.startGate(context.Background(), RingAlloc{NewCfgMb: 1, TotalCfgMb: 1}))
	assert.Equal(t, reads, f.reader.reads)
	assert.Len(t, f.reports, reports)
	assert.Equal(t, stops, f.count("Kill"))
}

func TestSyncerMemFuse_clear(t *testing.T) {
	fused := func(t *testing.T) *fuseFixture {
		f := newFuseFixture(t, 100, 100)
		f.apply(t, fuseStrategy(1, true, false))
		f.apply(t, fuseStrategy(2, true, true))
		require.Equal(t, memfuse.Fused, f.s.fuse.State())
		return f
	}

	t.Run("enabled_check_passes", func(t *testing.T) {
		f := fused(t)
		f.reader.avail = 1000
		f.apply(t, fuseStrategy(3, true, false))
		assert.Equal(t, 1, f.count("Update"))
		assert.Equal(t, memfuse.Armed, f.s.fuse.State())
		assert.Equal(t, "armed", f.memFuseState(t))
	})
	t.Run("enabled_check_fails_new_round", func(t *testing.T) {
		f := fused(t)
		reports := len(f.reports)
		f.apply(t, fuseStrategy(3, true, false))
		assert.Zero(t, f.count("Update"))
		assert.Len(t, f.reports, reports+1, "a new round is reported at once")
		assert.Equal(t, "startup", *f.lastReport(t).MemFuse.Reason)
	})
	t.Run("disabled_no_check", func(t *testing.T) {
		f := fused(t)
		reads := f.reader.reads
		f.apply(t, fuseStrategy(3, false, false))
		assert.Equal(t, 1, f.count("Update"))
		assert.Equal(t, reads, f.reader.reads)
		assert.Equal(t, memfuse.Disabled, f.s.fuse.State())
	})
}

func (f *fuseFixture) memFuseState(t *testing.T) string {
	t.Helper()
	f.s.syncMetric(context.Background())
	return f.lastReport(t).MemFuse.State
}

func TestSyncerMemFuse_switchOffSkipsChecks(t *testing.T) {
	f := newFuseFixture(t, 100, 0)
	f.apply(t, fuseStrategy(1, false, false))
	assert.Equal(t, 1, f.count("Update"))
	f.s.onFuseTick(context.Background())
	assert.Zero(t, f.reader.reads)
	assert.Equal(t, "disabled", f.memFuseState(t))
	assert.Equal(t, uint64(200), f.lastReport(t).MemFuse.NicBufferMb)
	assert.Nil(t, f.lastReport(t).MemFuse.Reason)
}

// CPM says fused while the worker runs (should not happen): it is killed, not left to exit gracefully.
func TestSyncerMemFuse_fusedPerCpmKillsRunningWorker(t *testing.T) {
	f := newFuseFixture(t, 100, 100000)
	f.apply(t, fuseStrategy(1, true, false))
	require.Equal(t, 1, f.count("Update"))

	f.apply(t, fuseStrategy(2, true, true))
	assert.Equal(t, 1, f.count("Kill"))
	assert.Zero(t, f.count("Stop"))
	assert.Equal(t, memfuse.Fused, f.s.fuse.State())
}

// After a restart CPM says fused: the worker is not started, and the report must not look like a new round.
func TestSyncerMemFuse_restoredFused(t *testing.T) {
	f := newFuseFixture(t, 100, 100000)
	res := fuseStrategy(5, true, true)
	f.apply(t, res)
	assert.Zero(t, f.count("Update"))
	assert.Same(t, res.Response, f.s.syncResp)
	assert.Equal(t, memfuse.Fused, f.s.fuse.State())
	assert.Empty(t, f.reports)

	assert.Zero(t, f.count("Kill"), "nothing running, nothing killed")

	f.s.syncMetric(context.Background())
	rep := f.lastReport(t)
	assert.Equal(t, "armed", rep.MemFuse.State)
	assert.Nil(t, rep.MemFuse.FusedTimestamp)
	assert.Equal(t, memfuse.Fused, f.s.fuse.State())
}

func TestSyncerMemFuse_daemonIdChangeResets(t *testing.T) {
	f := newFuseFixture(t, 100, 100)
	f.apply(t, fuseStrategy(1, true, false))
	require.Equal(t, memfuse.Fused, f.s.fuse.State())

	f.s.client.(*testClient).registerFn = func(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
		return &RegisterResponse{Id: 2}, nil
	}
	stops := f.count("Stop")
	require.NoError(t, f.s.doRegister(context.Background()))
	assert.Equal(t, stops+1, f.count("Stop"))
	assert.Equal(t, memfuse.Disabled, f.s.fuse.State())
	assert.Nil(t, f.s.fuse.Snapshot())
}
