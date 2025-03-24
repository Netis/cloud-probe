package cpm

import (
	"context"
	"log/slog"

	"github.com/pkg/errors"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/agent"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/slogx"
)

type AgentManager struct {
	agent *agent.Agent
	lg    *slog.Logger
}

func NewAgentManager() *AgentManager {
	return &AgentManager{
		lg: slog.Default().With(slogx.LoggerName("cpm.agentMgr")),
	}
}

func (m *AgentManager) IsAlive(ctx context.Context) (bool, error) {
	if m.agent == nil {
		return false, nil
	}
	return m.agent.IsAlive(ctx)
}

func (m *AgentManager) CreateIfDead(ctx context.Context, res *SyncStrategyResponse) error {
	if m.agent != nil {
		isAlive, err := m.agent.IsAlive(ctx)
		if err != nil {
			return err
		}
		if isAlive {
			return errors.New("agent is running")
		}
		m.agent = nil
	}

	return m.Create(ctx, res)
}

func (m *AgentManager) Update(ctx context.Context, res *SyncStrategyResponse) error {
	if m.agent != nil {
		if err := m.agent.Stop(); err != nil {
			return errors.Wrap(err, "stop agent failed")
		}
		m.agent = nil
	}
	return m.Create(ctx, res)
}

func (m *AgentManager) Create(ctx context.Context, res *SyncStrategyResponse) error {
	if m.agent != nil {
		return errors.New("agent is already exists")
	}

	var tasks []agent.TaskConfig

	for _, strategy := range res.Strategy {
		switch {
		case len(strategy.ContainerIds) > 0:
		case len(strategy.InterfaceNames) > 0:
		case len(strategy.InstanceNames) > 0:
		default:
			m.lg.Warn("No instance or interface or container in the strategy")
		}
	}

	m.agent = &agent.Agent{
		CpuLimit: res.CpuLimit,
		MemLimit: res.MemLimit,
		Tasks:    tasks,
	}
	return m.agent.Start(ctx)
}
