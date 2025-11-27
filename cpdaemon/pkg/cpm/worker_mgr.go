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
	"github.com/samber/lo"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/cgroup"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/worker"
	"github.com/Netis/cloud-probe/cpgolib/cpworker"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

const (
	UpdatePolicyRestart = "restart"
	UpdatePolicyReload  = "reload"
)

const (
	MemoryPolicyAutoNicBuffer  = "auto_nic_buffer"
	MemoryPolicyFixedNicBuffer = "fixed_nic_buffer"
)

type LibpcapMemConfig struct {
	FixedBufferSizeMb uint64
}

type MemoryConfig struct {
	Policy         string
	DefaultLimitMb uint64
	Libpcap        LibpcapMemConfig
}

type PipelineConfig struct {
	MinBufferSizeMb uint64
}

type WorkerConfig struct {
	PidFile    string
	ConfigFile string

	Executable string
	Env        map[string]string
	WorkDir    string
	CgroupCfg  cgroup.CgroupCfg

	CpuAffinity string
	LogLevel    string
	Control     worker.ControlConfig

	ExecutionModel string
	Pipeline       PipelineConfig

	UpdatePolicy string
	Memory       MemoryConfig
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

	if !slices.Contains([]string{worker.EXECUTION_MODEL_RTC, worker.EXECUTION_MODEL_PIPELINE}, c.ExecutionModel) {
		return errors.Errorf("invalid execution_model: %s", c.ExecutionModel)
	}

	switch c.Memory.Policy {
	case MemoryPolicyFixedNicBuffer:
		if c.Memory.Libpcap.FixedBufferSizeMb == 0 {
			return errors.Errorf("memoryPolicy.libpcap.bufferSizeMb must be greater than 0 when strategy is '%s'", MemoryPolicyFixedNicBuffer)
		}
	case MemoryPolicyAutoNicBuffer:
	default:
		return errors.Errorf("invalid memoryPolicy.strategy: %s", c.Memory.Policy)
	}

	switch c.UpdatePolicy {
	case UpdatePolicyReload:
	case UpdatePolicyRestart:
	default:
		return errors.Errorf("invalid updatePolicy: %s", c.UpdatePolicy)
	}
	return nil
}

type WorkerCreateResult struct {
	Warnings        []error
	BuffSizePerTask uint64
}

type TaskBuildResult struct {
	Tasks           []*worker.TaskConfig
	Warnings        []error
	BuffSizePerTask uint64
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

func (m *WorkerManager) Pid() int {
	m.mu.Lock()
	worker := m.worker
	m.mu.Unlock()

	if worker == nil {
		return 0
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

	return m.stopWorker(worker)
}

func (m *WorkerManager) stopWorker(worker *worker.Worker) error {
	if worker == nil {
		return nil
	}
	if err := worker.Stop(); err != nil {
		return errors.Wrap(err, "stop worker failed")
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

func (m *WorkerManager) CreateIfDead(
	ctx context.Context,
	res *SyncStrategyResponse,
	daemonUUID string,
	activeInstances []string,
) (*WorkerCreateResult, error) {
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

	return m.createUnlocked(ctx, res, daemonUUID, activeInstances)
}

func (m *WorkerManager) createUnlocked(
	ctx context.Context,
	res *SyncStrategyResponse,
	daemonUUID string,
	activeInstances []string,
) (*WorkerCreateResult, error) {
	if m.worker != nil {
		return nil, errors.New("worker is already exists")
	}

	buildResult, err := m.buildTasks(res, daemonUUID, activeInstances)
	if err != nil {
		return nil, err
	}

	for _, warning := range buildResult.Warnings {
		m.lg.Warn(warning.Error())
	}
	if len(buildResult.Tasks) == 0 {
		m.lg.Warn("no tasks")
		return &WorkerCreateResult{
			Warnings: buildResult.Warnings,
		}, nil
	}

	execCfg := worker.ExecConfig{
		PidFile:    m.workerCfg.PidFile,
		Executable: m.workerCfg.Executable,
		Env:        m.workerCfg.Env,
		WorkDir:    m.workerCfg.WorkDir,
		CgroupCfg:  m.workerCfg.CgroupCfg,
		ConfigFile: m.workerCfg.ConfigFile,
	}
	wCfg := m.newWorkerConfig(buildResult.Tasks, res)
	resLimit := worker.ResLimit{
		Cpu: res.CpuLimit,
		Mem: res.MemLimit,
	}

	if m.workerCfg.Control.Type == "unix" {
		socketPath := filepath.Clean(m.workerCfg.Control.Unix.Path)
		socketDir := filepath.Dir(socketPath)
		if err := os.MkdirAll(socketDir, 0o755); err != nil {
			return nil, errors.Wrapf(err, "create dir %s failed", socketDir)
		}
	}

	m.client, err = cpworker.NewClient(m.workerCfg.Control.ConnectString())
	if err != nil {
		return nil, errors.Wrap(err, "create worker client failed")
	}

	m.worker, err = worker.NewWorker("cpm", execCfg)
	if err != nil {
		m.client.Close()
		m.client = nil
		return nil, errors.Wrap(err, "create worker failed")
	}
	m.worker.SetLogger(m.baseLg)

	if err := m.worker.Start(ctx, wCfg); err != nil {
		return nil, err
	}
	if err := m.worker.UpdateResLimit(resLimit); err != nil {
		m.lg.Error("update resource limit failed, stopping worker", slogx.Error(err))
		m.worker.Stop()
		return nil, err
	}
	return &WorkerCreateResult{
		Warnings:        buildResult.Warnings,
		BuffSizePerTask: buildResult.BuffSizePerTask,
	}, nil
}

func (m *WorkerManager) Update(
	ctx context.Context,
	res *SyncStrategyResponse,
	daemonUUID string,
	activeInstances []string,
) (*WorkerCreateResult, error) {
	switch m.workerCfg.UpdatePolicy {
	case UpdatePolicyRestart:
		return m.updateByRestart(ctx, res, daemonUUID, activeInstances)
	case UpdatePolicyReload:
		return m.updateByReload(ctx, res, daemonUUID, activeInstances)
	default:
		return nil, errors.Errorf("unknown update policy: %s", m.workerCfg.UpdatePolicy)
	}
}

func (m *WorkerManager) updateByRestart(
	ctx context.Context,
	res *SyncStrategyResponse,
	daemonUUID string,
	activeInstances []string,
) (*WorkerCreateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.stopWorker(m.worker); err != nil {
		return nil, err
	}
	return m.createUnlocked(ctx, res, daemonUUID, activeInstances)
}

func (m *WorkerManager) updateByReload(
	ctx context.Context,
	res *SyncStrategyResponse,
	daemonUUID string,
	activeInstances []string,
) (*WorkerCreateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.worker == nil {
		return m.createUnlocked(ctx, res, daemonUUID, activeInstances)
	} else {
		return m.reloadConfig(ctx, res, daemonUUID, activeInstances)
	}
}

func (m *WorkerManager) reloadConfig(
	ctx context.Context,
	res *SyncStrategyResponse,
	daemonUUID string,
	activeInstances []string,
) (*WorkerCreateResult, error) {
	buildResult, err := m.buildTasks(res, daemonUUID, activeInstances)
	if err != nil {
		return nil, err
	}

	for _, warning := range buildResult.Warnings {
		m.lg.Warn(warning.Error())
	}

	if len(buildResult.Tasks) == 0 {
		m.lg.Warn("no tasks")
		if err := m.stopWorker(m.worker); err != nil {
			return nil, err
		}
		return &WorkerCreateResult{
			Warnings: buildResult.Warnings,
		}, nil
	}

	wCfg := m.newWorkerConfig(buildResult.Tasks, res)
	if err := m.worker.UpdateConfig(wCfg); err != nil {
		return nil, err
	}
	if m.client != nil {
		m.lg.Info("sending reload_config command to worker")
		if err := m.client.ReloadConfig(ctx); err != nil {
			return nil, errors.WithMessage(err, "send reload_config command failed")
		}
	} else {
		if err := m.worker.ReloadConfig(ctx); err != nil {
			return nil, err
		}
	}

	resLimit := worker.ResLimit{
		Cpu: res.CpuLimit,
		Mem: res.MemLimit,
	}
	if err := m.worker.UpdateResLimit(resLimit); err != nil {
		m.lg.Error("update resource limit failed, stopping worker", slogx.Error(err))
		m.worker.Stop()
		return nil, err
	}

	return &WorkerCreateResult{
		Warnings:        buildResult.Warnings,
		BuffSizePerTask: buildResult.BuffSizePerTask,
	}, nil
}

func (m *WorkerManager) buildTasks(
	res *SyncStrategyResponse,
	daemonUUID string,
	activeInstances []string,
) (*TaskBuildResult, error) {
	numItems := res.NumItems(activeInstances)
	if numItems == 0 {
		return &TaskBuildResult{}, nil
	}

	buffSizePerTask, err := m.getTaskBufferSizeMb(res, activeInstances)
	if err != nil {
		return nil, err
	}

	tb := &workerTaskBuilder{
		tool:            m.tool,
		daemonUUID:      daemonUUID,
		activeInstances: activeInstances,
		buffSize:        buffSizePerTask,
	}

	for _, strategy := range res.Strategy {
		tb.addStrategy(strategy)
	}
	tasks, warnings := tb.build()
	return &TaskBuildResult{
		Tasks:           tasks,
		Warnings:        warnings,
		BuffSizePerTask: buffSizePerTask,
	}, nil
}

func (m *WorkerManager) newWorkerConfig(tasks []*worker.TaskConfig, res *SyncStrategyResponse) *worker.Config {
	wCfg := &worker.Config{
		LogLevel:       m.workerCfg.LogLevel,
		Control:        m.workerCfg.Control,
		ExecutionModel: m.workerCfg.ExecutionModel,
		Tasks:          tasks,
	}

	if m.workerCfg.ExecutionModel == worker.EXECUTION_MODEL_PIPELINE {
		taskMem := lo.Sum(lo.Map(tasks, func(task *worker.TaskConfig, _ int) uint64 {
			switch task.Capturer.Type {
			case worker.CapturerType_Libpcap:
				if task.Capturer.Libpcap != nil && task.Capturer.Libpcap.BufferSizeMB != nil {
					return *task.Capturer.Libpcap.BufferSizeMB
				}
				// unreachable, but for safety
				// cpworker default buffer_size_mb
				return 256
			default:
				return 0
			}
		}))

		memLimit := m.workerCfg.Memory.DefaultLimitMb
		if res.MemLimit != nil && *res.MemLimit > 0 {
			memLimit = uint64(*res.MemLimit)
		}
		bufferSize := m.workerCfg.Pipeline.MinBufferSizeMb
		if memLimit > taskMem && memLimit-taskMem > bufferSize {
			bufferSize = memLimit - taskMem
		}
		wCfg.Pipeline = &worker.PipelineConfig{
			BufferSizeMB: bufferSize,
		}
	}
	if m.workerCfg.CpuAffinity != "" {
		wCfg.CpuAffinity = lo.ToPtr(m.workerCfg.CpuAffinity)
	}
	return wCfg
}

func (m *WorkerManager) getTaskBufferSizeMb(res *SyncStrategyResponse, activeInstances []string) (uint64, error) {
	switch m.workerCfg.Memory.Policy {
	case MemoryPolicyFixedNicBuffer:
		return m.workerCfg.Memory.Libpcap.FixedBufferSizeMb, nil
	case MemoryPolicyAutoNicBuffer:
		numItems := res.NumItems(activeInstances)
		if numItems == 0 {
			return 0, nil
		}

		memLimit := m.workerCfg.Memory.DefaultLimitMb
		if res.MemLimit != nil && *res.MemLimit > 0 {
			memLimit = uint64(*res.MemLimit)
		}
		if memLimit < uint64(numItems) {
			return 0, errors.Errorf("memory limit %d MB is too small for %d tasks", memLimit, numItems)
		}
		return memLimit / uint64(numItems), nil
	default:
		return 0, errors.Errorf("unknown memoryPolicy.strategy: %s", m.workerCfg.Memory.Policy)
	}
}
