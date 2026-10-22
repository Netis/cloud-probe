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

	if err := c.CgroupCfg.Validate(); err != nil {
		return err
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

// RingAlloc is what applying a strategy is about to allocate in the kernel capture ring.
type RingAlloc struct {
	// NewCfgMb is the configured buffer of the tasks that open a ring now: all tasks when the worker starts, the
	// tasks whose fingerprint changed on a reload.
	NewCfgMb uint64
	// TotalCfgMb is the configured buffer of all tasks after the apply.
	TotalCfgMb uint64
	MemLimitMb uint64
	// Pid is the running worker, 0 when none.
	Pid int
}

// StartGate is asked right before the capture ring is allocated; false refuses the apply. It runs under the
// manager's lock and must not call back into the manager.
type StartGate func(ctx context.Context, alloc RingAlloc) bool

var ErrStartRefused = errors.New("worker start refused by the start gate")

type WorkerManager struct {
	workerCfg WorkerConfig
	tool      Tool
	baseLg    *slog.Logger
	lg        *slog.Logger
	gate      StartGate

	mu     sync.Mutex
	client cpworker.Client
	worker *worker.Worker
	// current is the task set the running worker was last given.
	current []*worker.TaskConfig
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

func (m *WorkerManager) SetStartGate(gate StartGate) {
	m.gate = gate
}

func (m *WorkerManager) allow(ctx context.Context, alloc RingAlloc) bool {
	return m.gate == nil || m.gate(ctx, alloc)
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

// Kill stops the worker with SIGKILL: a memory fuse cannot wait for cpworker to drain its pipeline buffer.
func (m *WorkerManager) Kill() error {
	m.mu.Lock()
	worker := m.worker
	m.mu.Unlock()

	if worker == nil {
		return nil
	}
	if err := worker.Kill(); err != nil {
		return errors.Wrap(err, "kill worker failed")
	}
	m.reset()
	return nil
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
	m.current = nil
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

	// A start opens the ring of every task.
	ringMb := ringCfgMb(buildResult.Tasks)
	if !m.allow(ctx, RingAlloc{
		NewCfgMb:   ringMb,
		TotalCfgMb: ringMb,
		MemLimitMb: res.EffectiveMemLimitMb(m.workerCfg.Memory.DefaultLimitMb),
	}) {
		return nil, ErrStartRefused
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
	m.current = buildResult.Tasks
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

	// cpworker keeps the tasks whose fingerprint it already runs and opens a ring only for the others, before it
	// frees the rings of the tasks that went away. Nothing to allocate means nothing to ask.
	if newMb := newRingCfgMb(m.current, buildResult.Tasks); newMb > 0 {
		pid := 0
		if alive, _ := m.worker.IsAlive(ctx); alive {
			pid = m.worker.Pid()
		}
		if !m.allow(ctx, RingAlloc{
			NewCfgMb:   newMb,
			TotalCfgMb: ringCfgMb(buildResult.Tasks),
			MemLimitMb: res.EffectiveMemLimitMb(m.workerCfg.Memory.DefaultLimitMb),
			Pid:        pid,
		}) {
			return nil, ErrStartRefused
		}
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
	m.current = buildResult.Tasks

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
		taskMem := ringCfgMb(tasks)
		memLimit := res.EffectiveMemLimitMb(m.workerCfg.Memory.DefaultLimitMb)
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

// ringCfgMb is the configured capture buffer of the tasks.
func ringCfgMb(tasks []*worker.TaskConfig) uint64 {
	return lo.Sum(lo.Map(tasks, func(task *worker.TaskConfig, _ int) uint64 {
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
}

// newRingCfgMb is the configured capture buffer of the tasks of next that current does not run, by fingerprint.
func newRingCfgMb(current, next []*worker.TaskConfig) uint64 {
	running := make(map[string]struct{}, len(current))
	for _, task := range current {
		if task.Fingerprint != nil {
			running[*task.Fingerprint] = struct{}{}
		}
	}
	return ringCfgMb(lo.Filter(next, func(task *worker.TaskConfig, _ int) bool {
		if task.Fingerprint == nil {
			return true
		}
		_, ok := running[*task.Fingerprint]
		return !ok
	}))
}

// NicBufferTotalMb is the configured capture buffer of all tasks of the strategy.
func (m *WorkerManager) NicBufferTotalMb(res *SyncStrategyResponse, activeInstances []string) (uint64, error) {
	perTask, err := m.getTaskBufferSizeMb(res, activeInstances)
	if err != nil {
		return 0, err
	}
	return perTask * uint64(res.NumItems(activeInstances)), nil
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

		memLimit := res.EffectiveMemLimitMb(m.workerCfg.Memory.DefaultLimitMb)
		if memLimit < uint64(numItems) {
			return 0, errors.Errorf("memory limit %d MB is too small for %d tasks", memLimit, numItems)
		}
		return memLimit / uint64(numItems), nil
	default:
		return 0, errors.Errorf("unknown memoryPolicy.strategy: %s", m.workerCfg.Memory.Policy)
	}
}
