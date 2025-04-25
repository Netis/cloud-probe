package cpm

import (
	"context"
	"log/slog"
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

func (r *testWorkerManagerRecoder) CreateIfDead(ctx context.Context, resp *SyncStrategyResponse, daemonUUID string, activeInstances []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "CreateIfDead")
	if r.isAlive {
		return nil
	}
	r.isAlive = true
	r.pid = len(r.calls)
	r.startTime = time.Now()
	return nil
}

func (r *testWorkerManagerRecoder) Update(ctx context.Context, resp *SyncStrategyResponse, daemonUUID string, activeInstances []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Update")
	r.isAlive = true
	r.pid = len(r.calls)
	r.startTime = time.Now()
	return nil
}

func (r *testWorkerManagerRecoder) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Stop")
	r.isAlive = false
	return nil
}

func (r *testWorkerManagerRecoder) CollectStats(ctx context.Context) (cpworker.Stats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "CollectStats")
	return cpworker.Stats{}, nil
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

func (r *testWorkerManagerRecoder) Pid() (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Pid")
	if r.isAlive {
		return r.pid, true
	}
	return 0, false
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
)

type testClient struct {
	mu sync.Mutex

	registerFn     testRegisterFn
	syncStrategyFn testSyncStrategyFn
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
	return nil
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
			UuidFile:   "testdata/tmp/uuid",
		},
		RegRetryInterval:     100 * time.Millisecond,
		SyncStrategyInterval: 100 * time.Millisecond,
		SyncMetricInterval:   100 * time.Millisecond,
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
