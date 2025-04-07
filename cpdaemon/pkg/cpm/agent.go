package cpm

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/samber/lo"
	flag "github.com/spf13/pflag"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/agent"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/cgroup"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/tool"
	"github.com/Netis/cloud-probe/cpgolib/agentclient"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

type VirshCmdExecutor interface {
	ListNames() ([]string, error)
	ListInterfaces(vmName string) ([]string, error)
}

type ContainerCmdExecutor interface {
	GetHostPid(containerId string) (int, error)
}

type AgentFactory interface {
	NewAgent(name string, cfg agent.AgentRunTimeConfig) (*agent.Agent, error)
}

type AgentFactoryFunc func(name string, cfg agent.AgentRunTimeConfig) (*agent.Agent, error)

func (f AgentFactoryFunc) NewAgent(name string, cfg agent.AgentRunTimeConfig) (*agent.Agent, error) {
	return f(name, cfg)
}

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
	agentCfg     AgentConfig
	agentFactory AgentFactory
	tool         tool.Tool
	lg           *slog.Logger

	mu     sync.Mutex
	client *agentclient.Client
	agent  *agent.Agent
}

func NewAgentManager(
	agentCfg AgentConfig,
	agentFactory AgentFactory,
	tool tool.Tool,
) *AgentManager {
	return &AgentManager{
		agentCfg:     agentCfg,
		agentFactory: agentFactory,
		tool:         tool,
		lg:           slog.Default().With(slogx.LoggerName("cpm.agentMgr")),
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

func (m *AgentManager) Create(ctx context.Context, res *SyncStrategyResponse, activeInstances []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.createUnsafe(ctx, res, activeInstances)
}

func (m *AgentManager) createUnsafe(ctx context.Context, res *SyncStrategyResponse, activeInstances []string) error {
	if m.agent != nil {
		return errors.New("agent is already exists")
	}

	numItems := res.NumItems(activeInstances)
	if numItems == 0 {
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

	m.agent, err = m.agentFactory.NewAgent("cpm", cfg)
	if err != nil {
		return errors.Wrap(err, "create agent failed")
	}
	m.agent.SetLogger(m.lg.With(slogx.LoggerName("agent"), slog.String("name", "cpm")))

	return m.agent.Start(ctx)
}

type tasksBuilder struct {
	tool            tool.Tool
	activeInstances []string
	buffSize        uint64

	warnings []error
	tasks    []agent.TaskConfig
}

func (b *tasksBuilder) addStrategy(strategy StrategyEntry) {
	// check strategy is valid
	_, err := b.newTaskConfig(strategy, taskItem{nicName: "eth0", obsIdx: 0})
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}

	switch {
	case len(strategy.ContainerIds) > 0:
		b.addContainerIds(strategy)
	case len(strategy.InterfaceNames) > 0:
		for i, interfaceName := range strategy.InterfaceNames {
			b.addInterfaceName(strategy, interfaceName, i)
		}
	case len(strategy.InstanceNames) > 0:
		for i, instanceName := range strategy.InstanceNames {
			b.addInstanceName(strategy, instanceName, i)
		}
	}
}

func (b *tasksBuilder) addContainerIds(strategy StrategyEntry) {
	var idx int
	for _, containerId := range strategy.ContainerIds {
		// 来源旧版本C++实现，支持多个连续的下划线
		parts := strings.FieldsFunc(containerId, func(r rune) bool {
			return r == '_'
		})

		if len(parts) == 0 {
			b.warnings = append(b.warnings, errors.Errorf("invalid container id: %s", containerId))
			continue
		}

		nics := parts[1:]
		if len(nics) == 0 {
			nics = []string{"eth0"}
		}

		hostPid, err := b.tool.GetContainerHostPid(containerId)
		if err != nil {
			b.warnings = append(b.warnings, errors.Wrapf(err, "get container host process id failed: %s", containerId))
			idx += len(nics)
			continue
		}

		for _, nic := range nics {
			b.addContainerId(strategy, hostPid, nic, idx)
			idx++
		}
	}
}

func (b *tasksBuilder) addContainerId(strategy StrategyEntry, hostPid int, nic string, obsIdx int) {
	item := taskItem{
		nicName:     nic,
		netns:       fmt.Sprintf("/proc/%d/ns/net", hostPid),
		obsIdx:      obsIdx,
		dumpSubDirs: []string{strconv.Itoa(hostPid), nic},
	}

	task, err := b.newTaskConfig(strategy, item)
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}
	b.tasks = append(b.tasks, *task)
}

func (b *tasksBuilder) addInterfaceName(strategy StrategyEntry, interfaceName string, obsIdx int) {
	item := taskItem{
		nicName:     interfaceName,
		obsIdx:      obsIdx,
		dumpSubDirs: []string{interfaceName},
	}

	task, err := b.newTaskConfig(strategy, item)
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}
	b.tasks = append(b.tasks, *task)
}

func (b *tasksBuilder) addInstanceName(strategy StrategyEntry, instanceName string, obsIdx int) {
	if !slices.Contains(b.activeInstances, instanceName) {
		b.warnings = append(b.warnings, errors.Errorf("instance name not found: %s", instanceName))
		return
	}

	ifs, err := b.tool.GetKvmInstanceNics(instanceName)
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}
	if len(ifs) == 0 {
		b.warnings = append(b.warnings, errors.Errorf("instance %s has no interfaces", instanceName))
		return
	}

	item := taskItem{
		nicName:     ifs[0],
		obsIdx:      obsIdx,
		dumpSubDirs: []string{ifs[0]},
	}
	task, err := b.newTaskConfig(strategy, item)
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}

	b.tasks = append(b.tasks, *task)
}

func (b *tasksBuilder) newTaskConfig(strategy StrategyEntry, item taskItem) (*agent.TaskConfig, error) {
	task := agent.TaskConfig{
		Capturer: agent.CapturerConfig{
			Type: agent.CapturerType_Libpcap,
			Libpcap: &agent.LibpcapConfig{
				BufferSizeMB: lo.ToPtr(b.buffSize),
			},
		},
	}

	if strategy.Bpf != nil {
		task.Capturer.Libpcap.Bpf = strategy.Bpf
	}

	if strategy.Startup != nil {
		startupArgs, err := parseStartup(*strategy.Startup, true)
		if err != nil {
			return nil, errors.Wrapf(err, "parse startup failed: %s", *strategy.Startup)
		}
		if startupArgs.Snaplen != nil {
			task.Snaplen = lo.ToPtr(*startupArgs.Snaplen)
		}
		if startupArgs.Timeout != nil {
			task.Capturer.Libpcap.TimeoutMs = lo.ToPtr(int(*startupArgs.Timeout))
		}
	}

	if strategy.ReqPatternType != nil {
		switch *strategy.ReqPatternType {
		case ReqPatternType_AUTO:
			task.ReqPattern = &agent.ReqPattern{
				Type: agent.ReqPatternType_AUTO,
			}
		case ReqPatternType_CUSTOM:
			task.ReqPattern = &agent.ReqPattern{
				Type:   agent.ReqPatternType_CUSTOM,
				Custom: &agent.CustomReqPattern{},
			}
			if strategy.ReqPattern != nil {
				task.ReqPattern.Custom.Pattern = *strategy.ReqPattern
			}
		}
	}

	output := agent.OutputConfig{}
	if strategy.SliceLen != nil && *strategy.SliceLen > 0 {
		output.Slice = lo.ToPtr(uint64(*strategy.SliceLen))
	}

	if strategy.ForwardRateLimit != nil && *strategy.ForwardRateLimit > 0 {
		output.RateLimitMbps = lo.ToPtr(uint64(*strategy.ForwardRateLimit))
	}

	switch strategy.PacketChannelType {
	case PacketChannelType_VXLAN:
		output.Type = agent.OutputType_Vxlan
		output.Vxlan = &agent.VxlanOutputConfig{
			Host: strategy.Address,
		}
		if strategy.Port != nil {
			output.Vxlan.Port = strategy.Port
		}

		if strategy.CapTime != nil {
			if *strategy.CapTime == 1 {
				output.Vxlan.CaptureTime = lo.ToPtr(true)
			} else {
				output.Vxlan.CaptureTime = lo.ToPtr(false)
			}
		}

		if strategy.ApiVersion == nil || *strategy.ApiVersion == "v1" {
			if strategy.HasServiceTag && strategy.ServiceTag != nil {
				output.Vxlan.Vni1 = lo.ToPtr(uint32(*strategy.ServiceTag))
			} else {
				output.Vxlan.Vni1 = lo.ToPtr(uint32(0xffffff))
			}
		} else {
			var tag Vni2Tag
			tag.ResourcePointDirection = 0
			if strategy.HasObservationTag {
				if len(strategy.ObservationDomainIds) > item.obsIdx {
					tag.ObservationDomainId = strategy.ObservationDomainIds[item.obsIdx]
				} else {
					tag.ObservationDomainId = 1
				}
				if len(strategy.ObservationPointIds) > item.obsIdx {
					tag.ObservationPointId = uint32(strategy.ObservationPointIds[item.obsIdx])
				} else {
					tag.ObservationPointId = 1
				}
			} else {
				tag.ObservationDomainId = 1
				tag.ObservationPointId = 1
			}
			if strategy.HasExtensionFlag && strategy.ExtensionFlag != nil {
				tag.ExtensionFlag = uint32(*strategy.ExtensionFlag)
			} else {
				tag.ExtensionFlag = 0
			}
			output.Vxlan.Vni2 = lo.ToPtr(tag.Encode())
		}

	case PacketChannelType_GRE:
		output.Type = agent.OutputType_Gre
		output.Gre = &agent.GreOutputConfig{
			Host: strategy.Address,
		}
		if strategy.HasServiceTag && strategy.ServiceTag != nil {
			output.Gre.ServiceTag = lo.ToPtr(uint32(*strategy.ServiceTag))
		}
	case PacketChannelType_ZMQ:
		output.Type = agent.OutputType_Zmq
		output.Zmq = &agent.ZmqOutputConfig{
			Host: strategy.Address,
		}
		if strategy.Port != nil {
			output.Zmq.Port = int(*strategy.Port)
		} else {
			return nil, errors.New("missing zmq.port")
		}
		if strategy.HasServiceTag && strategy.ServiceTag != nil {
			output.Zmq.ServiceTag = lo.ToPtr(uint32(*strategy.ServiceTag))
		}
	case PacketChannelType_FILE:
		output.Type = agent.OutputType_RotatingFile
		if strategy.DumpDir == nil {
			return nil, errors.New("missing dumpDir")
		}

		dirParts := append([]string{*strategy.DumpDir}, item.dumpSubDirs...)
		fileRoot := filepath.Join(dirParts...)
		if err := os.MkdirAll(fileRoot, 0o755); err != nil {
			return nil, errors.Wrapf(err, "create dump dir failed: %s", fileRoot)
		}
		output.RotatingFile = &agent.RotatingFileOutputConfig{
			FileRoot: fileRoot,
		}
		if strategy.DumpInterval != nil {
			output.RotatingFile.MaxFileInterval = lo.ToPtr(int32(*strategy.DumpInterval))
		}
	default:
		return nil, errors.Errorf("packet channel type not supported: %s", strategy.PacketChannelType)
	}

	task.Outputs = append(task.Outputs, output)
	task.Interface = item.nicName
	if item.netns != "" {
		task.Netns = lo.ToPtr(item.netns)
	}
	return &task, nil
}

type taskItem struct {
	nicName string
	netns   string

	obsIdx      int
	dumpSubDirs []string
}

type Vni2Tag struct {
	ResourcePointDirection uint32 // 2bits
	ObservationPointId     uint32 // 5bits
	ExtensionFlag          uint32 // 1bit
	ObservationDomainId    uint32 // 24bits
}

func (t Vni2Tag) Encode() uint32 {
	return (t.ResourcePointDirection & 0x03) |
		(t.ObservationPointId&0x1F)<<2 |
		(t.ExtensionFlag&0x01)<<7 |
		(t.ObservationDomainId&0x00FFFFFF)<<8
}

type startupArgs struct {
	Snaplen *int
	Timeout *int
}

func parseStartup(startup string, ignoreUnknown bool) (*startupArgs, error) {
	args, err := splitArgs(startup)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	f := flag.NewFlagSet("", flag.ContinueOnError)
	snaplen := f.IntP("snaplen", "s", 0, "snaplen")
	timeout := f.IntP("timeout", "t", 0, "timeout")

	err = f.Parse(args)
	switch {
	case isUnknownFlagError(err):
		if !ignoreUnknown {
			return nil, errors.WithStack(err)
		}
	case err != nil:
		return nil, errors.WithStack(err)
	}

	res := &startupArgs{}
	if f.Changed("snaplen") {
		res.Snaplen = snaplen
	}
	if f.Changed("timeout") {
		res.Timeout = timeout
	}

	return res, nil
}
