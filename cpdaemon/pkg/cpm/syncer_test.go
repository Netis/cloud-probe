package cpm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Netis/cloud-probe/cpgolib/cpworker"
)

type testWorkerManagerRecoder struct {
	mu    sync.Mutex
	calls []string

	isAlive   bool
	pid       int
	startTime time.Time
}

func (r *testWorkerManagerRecoder) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *testWorkerManagerRecoder) CreateIfDead(
	ctx context.Context,
	resp *SyncStrategyResponse,
	daemonUUID string,
	activeInstances []string,
) (*WorkerCreateResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "CreateIfDead")
	if r.isAlive {
		return &WorkerCreateResult{}, nil
	}
	r.isAlive = true
	r.pid = len(r.calls)
	r.startTime = time.Now()
	return &WorkerCreateResult{}, nil
}

func (r *testWorkerManagerRecoder) Update(
	ctx context.Context,
	resp *SyncStrategyResponse,
	daemonUUID string,
	activeInstances []string,
) (*WorkerCreateResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Update")
	r.isAlive = true
	r.pid = len(r.calls)
	r.startTime = time.Now()
	return &WorkerCreateResult{}, nil
}

func (r *testWorkerManagerRecoder) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Stop")
	r.isAlive = false
	return nil
}

func (r *testWorkerManagerRecoder) CollectStatsSummary(ctx context.Context) (cpworker.StatsSummary, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "CollectStats")
	return cpworker.StatsSummary{}, nil
}

func (r *testWorkerManagerRecoder) IsAlive(ctx context.Context) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "IsAlive")
	return r.isAlive, nil
}

func (r *testWorkerManagerRecoder) StartTime() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "StartTime")
	if r.isAlive {
		return r.startTime
	}
	return time.Time{}
}

func (r *testWorkerManagerRecoder) Pid() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Pid")
	if r.isAlive {
		return r.pid
	}
	return 0
}

func (r *testWorkerManagerRecoder) kill() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.isAlive = false
}

func (r *testWorkerManagerRecoder) SetLogger(lg *slog.Logger) {
}

type (
	testRegisterFn     func(ctx context.Context, req RegisterRequest) (*RegisterResponse, error)
	testSyncStrategyFn func(ctx context.Context, daemonId int64, version int32) (*SyncStrategyResult, error)
	testSyncMetricsFn  func(ctx context.Context, daemonId int64, req SyncMetricsRequest) error
)

type testClient struct {
	mu sync.Mutex

	registerFn     testRegisterFn
	syncStrategyFn testSyncStrategyFn
	syncMetricsFn  testSyncMetricsFn
}

func (c *testClient) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.registerFn(ctx, req)
}

func (c *testClient) SyncStrategy(ctx context.Context, daemonId int64, version int32) (*SyncStrategyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.syncStrategyFn(ctx, daemonId, version)
}

func (c *testClient) SyncMetrics(ctx context.Context, daemonId int64, req SyncMetricsRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.syncMetricsFn == nil {
		return nil
	}
	return c.syncMetricsFn(ctx, daemonId, req)
}

func TestSyncer(t *testing.T) {
	syncReqCh := make(chan struct{})
	syncRespCh := make(chan *SyncStrategyResult)

	client := &testClient{
		registerFn: func(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
			return &RegisterResponse{
				Id: 1234,
			}, nil
		},
		syncStrategyFn: func(ctx context.Context, daemonId int64, version int32) (*SyncStrategyResult, error) {
			syncReqCh <- struct{}{}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case resp := <-syncRespCh:
				return resp, nil
			}
		},
	}
	workerMgr := &testWorkerManagerRecoder{}

	syncer, err := newSyncer(client, workerMgr, testTool{}, SyncerConfig{
		RegCfg: RegConfig{
			PlatformId: "test",
			UuidFile:   "testdata/uuid",
		},
		RegRetryInterval:        100 * time.Millisecond,
		SyncStrategyInterval:    100 * time.Millisecond,
		SyncMetricInterval:      100 * time.Millisecond,
		NicChangeDetectInterval: 100 * time.Millisecond,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitCh := make(chan struct{})
	go func() {
		syncer.Run(ctx)
		close(exitCh)
	}()

	<-syncReqCh
	syncRespCh <- &SyncStrategyResult{
		Changed: true,
		Response: &SyncStrategyResponse{
			Id:           2345,
			DaemonId:     1234,
			Version:      1,
			SyncInterval: 10,
			Strategy: []StrategyEntry{
				{
					InterfaceNames:    []string{"eth0"},
					SliceLen:          lo.ToPtr[int32](0),
					BuffLimit:         lo.ToPtr[int64](64),
					Startup:           lo.ToPtr("-s 65535 -t 0"),
					PacketChannelType: "ZMQ",
					Address:           "127.0.0.1",
					Port:              lo.ToPtr[int32](5555),
				},
			},
		},
	}

	<-syncReqCh
	{
		// 第1次同步后
		calls := lo.Filter(workerMgr.Calls(), func(item string, index int) bool {
			return slices.Contains([]string{"CreateIfDead", "Update", "Stop"}, item)
		})
		assert.Equal(t, []string{"Update"}, calls)
	}
	syncRespCh <- &SyncStrategyResult{
		Changed: false,
	}

	<-syncReqCh
	{
		// 第2次同步后
		calls := lo.Filter(workerMgr.Calls(), func(item string, index int) bool {
			return slices.Contains([]string{"CreateIfDead", "Update", "Stop"}, item)
		})
		assert.Equal(t, []string{"Update"}, calls)
	}

	syncRespCh <- &SyncStrategyResult{
		Changed: true,
		Response: &SyncStrategyResponse{
			Id:           2345,
			DaemonId:     1234,
			Version:      2,
			SyncInterval: 10,
			Strategy: []StrategyEntry{
				{
					InterfaceNames:    []string{"eth0"},
					SliceLen:          lo.ToPtr[int32](0),
					BuffLimit:         lo.ToPtr[int64](256),
					Startup:           lo.ToPtr("-s 65535 -t 0"),
					PacketChannelType: "ZMQ",
					Address:           "127.0.0.1",
					Port:              lo.ToPtr[int32](5555),
				},
			},
		},
	}

	<-syncReqCh
	{
		// 第3次同步后
		calls := lo.Filter(workerMgr.Calls(), func(item string, index int) bool {
			return slices.Contains([]string{"CreateIfDead", "Update", "Stop"}, item)
		})
		assert.Equal(t, []string{"Update", "Update"}, calls)
	}

	syncRespCh <- &SyncStrategyResult{
		Changed: false,
	}

	<-syncReqCh
	{
		// 第4次同步后
		calls := lo.Filter(workerMgr.Calls(), func(item string, index int) bool {
			return slices.Contains([]string{"CreateIfDead", "Update", "Stop"}, item)
		})
		assert.Equal(t, []string{"Update", "Update"}, calls)
	}
	workerMgr.kill()
	syncRespCh <- &SyncStrategyResult{
		Changed: false,
	}

	<-syncReqCh
	{
		// 第5次同步后
		calls := lo.Filter(workerMgr.Calls(), func(item string, index int) bool {
			return slices.Contains([]string{"CreateIfDead", "Update", "Stop"}, item)
		})
		assert.Equal(t, []string{"Update", "Update", "CreateIfDead"}, calls)
	}

	cancel()
	<-exitCh
}

func TestNetworkInterfaces(t *testing.T) {
	nics, err := networkInterfaces()
	require.NoError(t, err)

	data, err := json.MarshalIndent(nics, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(data))
}

// newTestSyncer builds a syncer with its uuid file in a temporary directory.
func newTestSyncer(t *testing.T, client Client, workerMgr IWorkerManager, cfg SyncerConfig) *Syncer {
	t.Helper()
	cfg.RegCfg.PlatformId = "test"
	if cfg.RegCfg.UuidFile == "" {
		cfg.RegCfg.UuidFile = filepath.Join(t.TempDir(), "uuid")
	}
	s, err := newSyncer(client, workerMgr, testTool{}, cfg)
	require.NoError(t, err)
	return s
}

// CPM receives timestamps as whole seconds plus the microseconds within that second.
func TestSyncer_registerSendsStartTime(t *testing.T) {
	var got RegisterRequest
	client := &testClient{registerFn: func(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
		got = req
		return &RegisterResponse{Id: 1}, nil
	}}
	s := newTestSyncer(t, client, &testWorkerManagerRecoder{}, SyncerConfig{})
	s.startTime = time.Unix(1700000000, 123456789)

	require.NoError(t, s.doRegister(context.Background()))
	assert.Equal(t, int64(1700000000), got.StartTimestamp)
	assert.Equal(t, int64(123456), got.StartMicroTimestamp)
}

// A new daemon id from CPM means the strategy synced so far belongs to another registration:
// the worker is stopped and the sync state reset. The same id keeps both.
func TestSyncer_registerDaemonIdChange(t *testing.T) {
	for _, tc := range []struct {
		name     string
		regId    int64
		wantStop bool
	}{
		{"same_id", 1, false},
		{"new_id", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &testClient{registerFn: func(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
				return &RegisterResponse{Id: tc.regId}, nil
			}}
			workerMgr := &testWorkerManagerRecoder{}
			s := newTestSyncer(t, client, workerMgr, SyncerConfig{})
			s.syncResp = &SyncStrategyResponse{DaemonId: 1}

			require.NoError(t, s.doRegister(context.Background()))
			assert.Equal(t, tc.wantStop, slices.Contains(workerMgr.Calls(), "Stop"))
			assert.Equal(t, tc.wantStop, s.syncResp == nil)
		})
	}
}

// syncLoop retries a failed strategy sync SyncStrategyMaxRetries times, then returns the error.
func TestSyncer_syncStrategyRetries(t *testing.T) {
	var calls int
	client := &testClient{syncStrategyFn: func(ctx context.Context, daemonId int64, version int32) (*SyncStrategyResult, error) {
		calls++
		return nil, errors.New("cpm unreachable")
	}}
	s := newTestSyncer(t, client, &testWorkerManagerRecoder{}, SyncerConfig{
		SyncStrategyInterval:   time.Millisecond,
		SyncStrategyMaxRetries: 2,
		SyncMetricInterval:     time.Hour,
	})
	s.regResp = &RegisterResponse{Id: 1}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.ErrorContains(t, s.syncLoop(ctx), "cpm unreachable")
	assert.Equal(t, 3, calls, "one attempt plus SyncStrategyMaxRetries retries")
}

func TestSyncer_metricsSamplingTime(t *testing.T) {
	var got SyncMetricsRequest
	client := &testClient{syncMetricsFn: func(ctx context.Context, daemonId int64, req SyncMetricsRequest) error {
		got = req
		return nil
	}}
	workerMgr := &testWorkerManagerRecoder{isAlive: true, pid: os.Getpid()}
	s := newTestSyncer(t, client, workerMgr, SyncerConfig{})
	s.regResp = &RegisterResponse{Id: 1}

	before := time.Now().Unix()
	s.syncMetric(context.Background())
	require.NotNil(t, got.Metrics)
	assert.GreaterOrEqual(t, got.Metrics.SamplingTimestamp, before)
	assert.GreaterOrEqual(t, got.Metrics.SamplingMicroTimestamp, int64(0))
	assert.Less(t, got.Metrics.SamplingMicroTimestamp, int64(1e6))
	assert.Equal(t, lo.ToPtr(int32(os.Getpid())), got.Pid)
}

// The daemon keeps the uuid in its uuid file across restarts; an empty file gets a new one.
func TestSyncer_uuidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uuid")
	require.NoError(t, os.WriteFile(path, []byte("kept-uuid\n"), 0o644))
	s := newTestSyncer(t, &testClient{}, &testWorkerManagerRecoder{}, SyncerConfig{RegCfg: RegConfig{UuidFile: path}})
	assert.Equal(t, "kept-uuid", s.daemonUUID)

	require.NoError(t, os.WriteFile(path, nil, 0o644))
	s = newTestSyncer(t, &testClient{}, &testWorkerManagerRecoder{}, SyncerConfig{RegCfg: RegConfig{UuidFile: path}})
	require.NotEmpty(t, s.daemonUUID)
	saved, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, s.daemonUUID, string(saved))
}

// IncludingNICs limits the interfaces registered with CPM; empty registers all of them.
func TestSyncer_includingNICs(t *testing.T) {
	all, err := networkInterfaces()
	require.NoError(t, err)
	if len(all) < 2 {
		t.Skip("needs at least two network interfaces")
	}

	s := newTestSyncer(t, &testClient{}, &testWorkerManagerRecoder{}, SyncerConfig{})
	assert.Len(t, s.regNics, len(all))

	s = newTestSyncer(t, &testClient{}, &testWorkerManagerRecoder{}, SyncerConfig{
		RegCfg: RegConfig{IncludingNICs: []string{all[1].Name}},
	})
	require.Len(t, s.regNics, 1)
	assert.Equal(t, all[1].Name, s.regNics[0].Name)
}
