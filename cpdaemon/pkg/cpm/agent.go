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

	"github.com/Netis/cloud-probe/cpdaemon/pkg/agent"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/cgroup"
	"github.com/Netis/cloud-probe/cpgolib/agentclient"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

type AgentConfig struct {
	Executable string
	Env        map[string]string
	WorkDir    string
	CgroupCfg  cgroup.CgroupCfg

	LogLevel   string
	UnixSocket string
	TasksFile  string
}

func (c *AgentConfig) Validate() error {
	if !slices.Contains([]string{"DEBUG", "INFO", "WARN", "ERROR"}, strings.ToUpper(c.LogLevel)) {
		return errors.Errorf("invalid logLevel: %s", c.LogLevel)
	}
	return nil
}

type AgentManager struct {
	agentCfg AgentConfig
	tool     Tool
	lg       *slog.Logger

	mu     sync.Mutex
	client *agentclient.Client
	agent  *agent.Agent
}

func NewAgentManager(
	agentCfg AgentConfig,
	tool Tool,
) *AgentManager {
	return &AgentManager{
		agentCfg: agentCfg,
		tool:     tool,
		lg:       slog.Default().With(slogx.LoggerName("cpm.agentMgr")),
	}
}

func (m *AgentManager) SetLogger(lg *slog.Logger) {
	m.lg = lg
}

func (m *AgentManager) StartTime() time.Time {
	m.mu.Lock()
	agent := m.agent
	m.mu.Unlock()

	if agent == nil {
		return time.Time{}
	}
	return agent.StartTime()
}

func (m *AgentManager) Pid() (int, bool) {
	m.mu.Lock()
	agent := m.agent
	m.mu.Unlock()

	if agent == nil {
		return 0, false
	}
	return agent.Pid()
}

func (m *AgentManager) IsAlive(ctx context.Context) (bool, error) {
	m.mu.Lock()
	agent := m.agent
	m.mu.Unlock()

	if agent == nil {
		return false, nil
	}
	return agent.IsAlive(ctx)
}

func (m *AgentManager) Stop() error {
	m.mu.Lock()
	agent := m.agent
	m.mu.Unlock()

	if agent == nil {
		return nil
	}
	return agent.Stop()
}

func (m *AgentManager) CollectStats(ctx context.Context) (agentclient.Stats, error) {
	m.mu.Lock()
	client := m.client
	m.mu.Unlock()

	if client == nil {
		return agentclient.Stats{}, nil
	}
	return client.CollectStats(ctx)
}

func (m *AgentManager) CreateIfDead(ctx context.Context, res *SyncStrategyResponse, activeInstances []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.agent != nil {
		isAlive, err := m.agent.IsAlive(ctx)
		if err != nil {
			return err
		}
		if isAlive {
			return errors.New("agent is still running")
		}

		m.agent = nil
		if m.client != nil {
			m.client.Close()
			m.client = nil
		}
	}

	return m.createUnsafe(ctx, res, activeInstances)
}

func (m *AgentManager) Update(ctx context.Context, res *SyncStrategyResponse, activeInstances []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.agent != nil {
		if err := m.agent.Stop(); err != nil {
			return errors.Wrap(err, "stop agent failed")
		}

		m.agent = nil
		if m.client != nil {
			m.client.Close()
			m.client = nil
		}
	}
	return m.createUnsafe(ctx, res, activeInstances)
}

func (m *AgentManager) createUnsafe(ctx context.Context, res *SyncStrategyResponse, activeInstances []string) error {
	if m.agent != nil {
		return errors.New("agent is already exists")
	}

	numItems := res.NumItems(activeInstances)
	if numItems == 0 {
		// 策略为空
		return nil
	}

	buffSize := uint64(256)
	if res.MemLimit != nil && *res.MemLimit > 0 {
		if *res.MemLimit < int64(numItems) {
			return errors.New("mem limit small than number of strategy items")
		}
		buffSize = uint64(*res.MemLimit) / uint64(numItems)
	}

	tb := &tasksBuilder{
		tool:            m.tool,
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

	cfg := agent.AgentRunTimeConfig{
		Executable: m.agentCfg.Executable,
		Env:        m.agentCfg.Env,
		WorkDir:    m.agentCfg.WorkDir,
		CgroupCfg:  m.agentCfg.CgroupCfg,
		LogLevel:   m.agentCfg.LogLevel,
		UnixSocket: m.agentCfg.UnixSocket,
		TasksFile:  m.agentCfg.TasksFile,
		Tasks:      tb.tasks,

		CpuLimit: res.CpuLimit,
		MemLimit: res.MemLimit,
	}

	socketPath := filepath.Clean(cfg.UnixSocket)
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return errors.Wrapf(err, "create dir %s failed", dir)
	}

	var err error
	m.client, err = agentclient.New(socketPath)
	if err != nil {
		return errors.Wrap(err, "create agent client failed")
	}

	m.agent, err = agent.NewAgent("cpm", cfg)
	if err != nil {
		return errors.Wrap(err, "create agent failed")
	}
	m.agent.SetLogger(m.lg.With(slogx.LoggerName("agent"), slog.String("name", "cpm")))

	return m.agent.Start(ctx)
}
