package cpm

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/cgroup"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/worker"
	"github.com/Netis/cloud-probe/cpgolib/cpworker"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

type WorkerConfig struct {
	PidFile    string
	ConfigFile string

	Executable string
	Env        map[string]string
	WorkDir    string
	CgroupCfg  cgroup.CgroupCfg

	CpuAffinity int
	LogLevel    string
	Control     worker.ControlConfig
}

func (c *WorkerConfig) Validate() error {
	if !slices.Contains([]string{"DEBUG", "INFO", "WARN", "ERROR"}, strings.ToUpper(c.LogLevel)) {
		return errors.Errorf("invalid logLevel: %s", c.LogLevel)
	}
	switch c.Control.Type {
	case "unix":
		if c.Control.Unix == nil || c.Control.Unix.Path == "" {
			return errors.New("require control.unix.path")
		}
	default:
		return errors.Errorf("invalid control.type: %s", c.Control.Type)
	}
	return nil
}

type WorkerCreateResult struct {
	Warnings []error
}

type WorkerManager struct {
	workerCfg WorkerConfig
	tool      Tool
	baseLg    *slog.Logger
	lg        *slog.Logger

	mu              sync.Mutex
	client          cpworker.Client
	worker          *worker.Worker
	buffSizePerTask uint64
}

func NewWorkerManager(
	workerCfg WorkerConfig,
	tool Tool,
) *WorkerManager {
	return &WorkerManager{
		workerCfg: workerCfg,
		tool:      tool,
		baseLg:    slog.Default(),
		lg:        slog.Default().With(slogx.LoggerName("cpm.workerMgr")),
	}
}

func (m *WorkerManager) SetLogger(lg *slog.Logger) {
	m.baseLg = lg
	m.lg = lg.With(slogx.LoggerName("cpm.workerMgr"))
}

func (m *WorkerManager) StartTime() time.Time {
	m.mu.Lock()
	worker := m.worker
	m.mu.Unlock()

	if worker == nil {
		return time.Time{}
	}
	return worker.StartTime()
}

func (m *WorkerManager) Pid() int {
	m.mu.Lock()
	worker := m.worker
	m.mu.Unlock()

	if worker == nil {
		return 0
	}
	return worker.Pid()
}

func (m *WorkerManager) BuffSizePerTask() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buffSizePerTask
}

func (m *WorkerManager) IsAlive(ctx context.Context) (bool, error) {
	m.mu.Lock()
	worker := m.worker
	m.mu.Unlock()

	if worker == nil {
		return false, nil
	}
	return worker.IsAlive(ctx)
}

func (m *WorkerManager) Stop() error {
	m.mu.Lock()
	worker := m.worker
	m.mu.Unlock()

	if worker == nil {
		return nil
	}
	if err := worker.Stop(); err != nil {
		return err
	}
	m.reset()
	return nil
}

func (m *WorkerManager) reset() {
	m.worker = nil
	if m.client != nil {
		m.client.Close()
		m.client = nil
	}
	m.buffSizePerTask = 0
}

func (m *WorkerManager) CollectStatsSummary(ctx context.Context) (cpworker.StatsSummary, error) {
	m.mu.Lock()
	client := m.client
	m.mu.Unlock()

	if client == nil {
		return cpworker.StatsSummary{}, nil
	}
	return client.CollectStatsSummary(ctx)
}

func (m *WorkerManager) CreateIfDead(ctx context.Context, res *SyncStrategyResponse, daemonUUID string, activeInstances []string) (*WorkerCreateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.worker != nil {
		isAlive, err := m.worker.IsAlive(ctx)
		if err != nil {
			return nil, err
		}
		if isAlive {
			return nil, errors.New("worker is still running")
		}

		m.reset()
	}

	return m.createUnsafe(ctx, res, daemonUUID, activeInstances)
}

func (m *WorkerManager) Update(ctx context.Context, res *SyncStrategyResponse, daemonUUID string, activeInstances []string) (*WorkerCreateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.worker != nil {
		if err := m.worker.Stop(); err != nil {
			return nil, errors.Wrap(err, "stop worker failed")
		}
		m.reset()
	}
	return m.createUnsafe(ctx, res, daemonUUID, activeInstances)
}

func (m *WorkerManager) createUnsafe(ctx context.Context, res *SyncStrategyResponse, daemonUUID string, activeInstances []string) (*WorkerCreateResult, error) {
	if m.worker != nil {
		return nil, errors.New("worker is already exists")
	}

	numItems := res.NumItems(activeInstances)
	if numItems == 0 {
		// 策略为空
		m.lg.Info("skip create worker: strategy is empty")
		return &WorkerCreateResult{}, nil
	}

	buffSizePerTask := uint64(256)
	if res.MemLimit != nil && *res.MemLimit > 0 {
		if *res.MemLimit < int64(numItems) {
			return nil, errors.New("memory limit small than number of strategy items")
		}
		buffSizePerTask = uint64(*res.MemLimit) / uint64(numItems)
	}

	tb := &workerTasksBuilder{
		tool:            m.tool,
		daemonUUID:      daemonUUID,
		activeInstances: activeInstances,
		buffSize:        buffSizePerTask,
	}

	for _, strategy := range res.Strategy {
		tb.addStrategy(strategy)
	}

	// TODO: 周期性输出
	for _, warning := range tb.warnings {
		m.lg.Warn(warning.Error())
	}

	if len(tb.tasks) == 0 {
		m.lg.Warn("no tasks")
		return &WorkerCreateResult{
			Warnings: tb.warnings,
		}, nil
	}

	cfg := worker.ExecConfig{
		PidFile:    m.workerCfg.PidFile,
		Executable: m.workerCfg.Executable,
		Env:        m.workerCfg.Env,
		WorkDir:    m.workerCfg.WorkDir,
		CgroupCfg:  m.workerCfg.CgroupCfg,

		CpuAffinity: m.workerCfg.CpuAffinity,
		LogLevel:    m.workerCfg.LogLevel,
		Control:     m.workerCfg.Control,
		Tasks:       tb.tasks,
		ConfigFile:  m.workerCfg.ConfigFile,

		CpuLimit: res.CpuLimit,
		MemLimit: res.MemLimit,
	}

	if cfg.Control.Type == "unix" {
		socketPath := filepath.Clean(cfg.Control.Unix.Path)
		socketDir := filepath.Dir(socketPath)
		if err := os.MkdirAll(socketDir, 0o755); err != nil {
			return nil, errors.Wrapf(err, "create dir %s failed", socketDir)
		}
	}

	var err error
	m.client, err = cpworker.NewClient(cfg.Control.ConnectString())
	if err != nil {
		return nil, errors.Wrap(err, "create worker client failed")
	}

	m.worker, err = worker.NewWorker("cpm", cfg)
	if err != nil {
		m.client.Close()
		m.client = nil
		return nil, errors.Wrap(err, "create worker failed")
	}
	m.worker.SetLogger(m.baseLg)
	m.buffSizePerTask = buffSizePerTask

	if err := m.worker.Start(ctx); err != nil {
		return nil, err
	}
	return &WorkerCreateResult{
		Warnings: tb.warnings,
	}, nil
}
