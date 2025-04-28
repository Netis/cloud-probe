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

type WorkerManager struct {
	workerCfg WorkerConfig
	tool      Tool
	baseLg    *slog.Logger
	lg        *slog.Logger

	mu     sync.Mutex
	client cpworker.Client
	worker *worker.Worker
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

func (m *WorkerManager) Pid() (int, bool) {
	m.mu.Lock()
	worker := m.worker
	m.mu.Unlock()

	if worker == nil {
		return 0, false
	}
	return worker.Pid()
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
	return worker.Stop()
}

func (m *WorkerManager) CollectStats(ctx context.Context) (cpworker.Stats, error) {
	m.mu.Lock()
	client := m.client
	m.mu.Unlock()

	if client == nil {
		return cpworker.Stats{}, nil
	}
	return client.CollectStats(ctx)
}

func (m *WorkerManager) CreateIfDead(ctx context.Context, res *SyncStrategyResponse, daemonUUID string, activeInstances []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.worker != nil {
		isAlive, err := m.worker.IsAlive(ctx)
		if err != nil {
			return err
		}
		if isAlive {
			return errors.New("worker is still running")
		}

		m.worker = nil
		if m.client != nil {
			m.client.Close()
			m.client = nil
		}
	}

	return m.createUnsafe(ctx, res, daemonUUID, activeInstances)
}

func (m *WorkerManager) Update(ctx context.Context, res *SyncStrategyResponse, daemonUUID string, activeInstances []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.worker != nil {
		if err := m.worker.Stop(); err != nil {
			return errors.Wrap(err, "stop worker failed")
		}
		m.worker = nil

		if m.client != nil {
			m.client.Close()
			m.client = nil
		}
	}
	return m.createUnsafe(ctx, res, daemonUUID, activeInstances)
}

func (m *WorkerManager) createUnsafe(ctx context.Context, res *SyncStrategyResponse, daemonUUID string, activeInstances []string) error {
	if m.worker != nil {
		return errors.New("worker is already exists")
	}

	numItems := res.NumItems(activeInstances)
	if numItems == 0 {
		// 策略为空
		m.lg.Info("skip create worker: strategy is empty")
		return nil
	}

	buffSize := uint64(256)
	if res.MemLimit != nil && *res.MemLimit > 0 {
		if *res.MemLimit < int64(numItems) {
			return errors.New("memory limit small than number of strategy items")
		}
		buffSize = uint64(*res.MemLimit) / uint64(numItems)
	}

	tb := &workerTasksBuilder{
		tool:            m.tool,
		daemonUUID:      daemonUUID,
		activeInstances: activeInstances,
		buffSize:        buffSize,
	}

	for _, strategy := range res.Strategy {
		tb.addStrategy(strategy)
	}

	for _, warning := range tb.warnings {
		m.lg.Warn(warning.Error())
	}

	if len(tb.tasks) == 0 {
		m.lg.Warn("no tasks")
		return nil
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
			return errors.Wrapf(err, "create dir %s failed", socketDir)
		}
	}

	var err error
	m.client, err = cpworker.NewClient(cfg.Control.ConnectString())
	if err != nil {
		return errors.Wrap(err, "create worker client failed")
	}

	m.worker, err = worker.NewWorker("cpm", cfg)
	if err != nil {
		return errors.Wrap(err, "create worker failed")
	}
	m.worker.SetLogger(m.baseLg)

	return m.worker.Start(ctx)
}
