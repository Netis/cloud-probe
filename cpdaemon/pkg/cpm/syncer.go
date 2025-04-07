package cpm

import (
	"context"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/agent"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/tool"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/version"
	"github.com/Netis/cloud-probe/cpgolib/agentclient"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

type RegConfig struct {
	Name          string
	UuidFile      string
	NodeName      string
	PlatformId    string
	DeployEnv     string
	Labels        []string
	IncludingNICs []string

	PodName   string
	Namespace string
}

func (c *RegConfig) Validate() error {
	if c.Name == "" {
		return errors.New("name is required")
	}
	if c.UuidFile == "" {
		return errors.New("uuidFile is required")
	}
	if c.PlatformId == "" {
		return errors.New("platformId is required")
	}
	if !slices.Contains([]string{DeployEnv_INSTANCE, DeployEnv_HOST}, c.DeployEnv) {
		return errors.Errorf("deployEnv must be %s or %s", DeployEnv_INSTANCE, DeployEnv_HOST)
	}
	return nil
}

type SyncerConfig struct {
	RegCfg               RegConfig
	RegRetryInterval     time.Duration
	SyncStrategyInterval time.Duration
	SyncMetricInterval   time.Duration
}

type Syncer struct {
	client   *HttpClient
	agentMgr *AgentManager
	tool     tool.Tool
	cfg      SyncerConfig

	daemonUUID        string
	startTime         time.Time
	networkInterfaces []NicEntry

	regResp             *RegisterResponse
	syncResp            *SyncStrategyResponse
	syncActiveInstances []string

	logBuf *SyncLogBuffer
	lg     *slog.Logger
}

func checkAgentRunning(unixSocket string) (bool, error) {
	agentClient, err := agentclient.New(unixSocket)
	if err != nil {
		return false, errors.Wrap(err, "create agent client")
	}
	defer agentClient.Close()

	err = agentClient.Dial(context.Background())
	if err == nil {
		return true, nil
	}
	return false, nil
}

func NewSyncer(
	client *HttpClient,
	agentCfg AgentConfig,
	tool tool.Tool,
	cfg SyncerConfig,
) (*Syncer, error) {
	if err := cfg.RegCfg.Validate(); err != nil {
		return nil, err
	}
	if err := agentCfg.Validate(); err != nil {
		return nil, err
	}

	// 检查agent是否正在运行，只有在cpdaemon被kill时才会出现这种情况
	running, err := checkAgentRunning(agentCfg.UnixSocket)
	if err != nil {
		return nil, errors.Wrap(err, "check agent running")
	}
	if running {
		return nil, errors.New("agent is running, please stop it first")
	}

	logBuf := &SyncLogBuffer{}
	lg := slog.New(slogx.Multiple(
		slog.Default().With(slogx.LoggerName("cpm.syncer")).Handler(),
		&SyncLogHandler{w: logBuf, level: slog.LevelDebug},
	))

	agentMgr := NewAgentManager(agentCfg, AgentFactoryFunc(agent.NewAgent), tool)
	agentMgr.SetLogger(lg.With(slogx.LoggerName("cpm.agentMgr")))

	s := &Syncer{
		client:   client,
		agentMgr: agentMgr,
		tool:     tool,
		cfg:      cfg,

		logBuf: logBuf,
		lg:     lg,

		startTime: time.Now(),
	}
	if err := s.init(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Syncer) init() error {
	if err := s.initUuid(); err != nil {
		return err
	}
	if err := s.initNetworkInterfaces(); err != nil {
		return err
	}
	return nil
}

func (s *Syncer) initUuid() error {
	if _, err := os.Stat(s.cfg.RegCfg.UuidFile); os.IsNotExist(err) {
		uuidVal := uuid.New().String()
		if err := os.WriteFile(s.cfg.RegCfg.UuidFile, []byte(uuidVal), 0o644); err != nil {
			return errors.Wrapf(err, "write uuid file %s", s.cfg.RegCfg.UuidFile)
		}
		s.daemonUUID = uuidVal
		return nil
	}

	b, err := os.ReadFile(s.cfg.RegCfg.UuidFile)
	if err != nil {
		return errors.Wrapf(err, "read uuid file %s", s.cfg.RegCfg.UuidFile)
	}
	uuidVal := strings.TrimSpace(string(b))
	if len(uuidVal) != 0 {
		s.daemonUUID = uuidVal
		return nil
	}

	uuidVal = uuid.New().String()
	if err := os.WriteFile(s.cfg.RegCfg.UuidFile, []byte(uuidVal), 0o644); err != nil {
		return errors.Wrapf(err, "write uuid file %s", s.cfg.RegCfg.UuidFile)
	}
	s.daemonUUID = uuidVal
	return nil
}

func (s *Syncer) initNetworkInterfaces() error {
	ifs, err := net.Interfaces()
	if err != nil {
		return errors.Wrap(err, "get network interfaces")
	}

	for _, intf := range ifs {
		nic := NicEntry{
			Index: intf.Index,
			Name:  intf.Name,
			Mac:   intf.HardwareAddr.String(),
			Flags: int(intf.Flags),
			Mtu:   intf.MTU,
		}

		addrs, err := intf.Addrs()
		if err != nil {
			return errors.Wrapf(err, "get interface %q addresses", intf.Name)
		}

		for _, addr := range addrs {
			nic.InetAddresses = append(nic.InetAddresses, addr.String())
		}
		s.networkInterfaces = append(s.networkInterfaces, nic)
	}
	return nil
}

func (s *Syncer) Run(ctx context.Context) error {
	for {
		err := s.registerLoop(ctx)
		switch {
		case errors.Is(err, context.Canceled):
			return nil
		case err != nil:
			panic(err)
		}

		err = s.syncStrategyLoop(ctx)
		switch {
		case errors.Is(err, context.Canceled):
			return nil
		case err != nil:
			s.lg.Error("sync loop error, will retry", slogx.Error(err))
			time.Sleep(2 * time.Second)
		}
	}
}

func (s *Syncer) registerLoop(ctx context.Context) error {
	tm := time.NewTimer(0)
	defer tm.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tm.C:
			err := s.doRegister(ctx)
			if err == nil {
				s.lg.Info("register success")
				return nil
			}

			s.lg.Error("register failed, will retry", slogx.Error(err))
			tm.Reset(s.cfg.RegRetryInterval)
		}
	}
}

func (s *Syncer) doRegister(ctx context.Context) error {
	nics := s.networkInterfaces
	if len(s.cfg.RegCfg.IncludingNICs) > 0 {
		nics = lo.Filter(nics, func(nic NicEntry, _ int) bool {
			return slices.Contains(s.cfg.RegCfg.IncludingNICs, nic.Name)
		})
	}

	res, err := s.client.Register(ctx, RegisterRequest{
		Name:               s.cfg.RegCfg.Name,
		UUID:               s.daemonUUID,
		NodeName:           s.cfg.RegCfg.NodeName,
		Namespace:          s.cfg.RegCfg.Namespace,
		PodName:            s.cfg.RegCfg.PodName,
		PlatformId:         s.cfg.RegCfg.PlatformId,
		ApiVersion:         ApiVersion_V1,
		SupportApiVersions: SupportApiVersions,
		DeployEnv:          s.cfg.RegCfg.DeployEnv,
		PaUUID:             s.daemonUUID,

		StartTimestamp:      s.startTime.Unix(),
		StartMicroTimestamp: s.startTime.UnixMicro() % 1e6,

		ClientVersion: version.Version,
		Labels: lo.Map(s.cfg.RegCfg.Labels, func(label string, _ int) LabelEntry {
			return LabelEntry{
				Value: label,
			}
		}),
		NetworkInterfaces: nics,
	})
	if err != nil {
		return err
	}

	s.regResp = res
	if s.syncResp != nil && s.regResp.Id != s.syncResp.DaemonId {
		s.lg.Info("daemon id changed, clear syncResp")
		s.syncResp = nil
	}
	return nil
}

func (s *Syncer) syncStrategyLoop(ctx context.Context) error {
	strategyTimer := time.NewTimer(0)
	defer strategyTimer.Stop()

	metricTimer := time.NewTimer(s.cfg.SyncMetricInterval)
	defer metricTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			if err := s.agentMgr.Stop(); err != nil {
				s.lg.Error("stop agent failed", slogx.Error(err))
			}
			return ctx.Err()
		case <-strategyTimer.C:
			var lastVersion int32
			if s.syncResp != nil {
				lastVersion = s.syncResp.Version
			}
			res, err := s.client.SyncStrategy(ctx, s.regResp.Id, lastVersion)
			if err != nil {
				return err
			}

			if err := s.applyStrategy(ctx, res); err != nil {
				s.lg.Error("apply strategy failed", slogx.Error(err))
			}
			strategyTimer.Reset(s.cfg.SyncStrategyInterval)
		case <-metricTimer.C:
			if err := s.syncMetric(ctx); err != nil {
				s.lg.Error("sync metric failed", slogx.Error(err))
			}
			metricTimer.Reset(s.cfg.SyncMetricInterval)
		}
	}
}

func (s *Syncer) applyStrategy(ctx context.Context, res *SyncStrategyResult) error {
	if !res.Changed {
		alive, err := s.agentMgr.IsAlive(ctx)
		if err != nil {
			s.lg.Info("agent check alive failed", slogx.Error(err))
			return nil
		}
		if !alive && s.syncResp != nil {
			activeInstances, err := s.activeInstancesIfRequired(s.syncResp)
			if err != nil {
				s.lg.Error("get active instances failed", slogx.Error(err))
			}

			numItems := s.syncResp.NumItems(activeInstances)
			if numItems == 0 {
				return nil
			}

			s.lg.Info(
				"agent is not alive, will restart",
				slog.Int("numItems", numItems),
			)

			if err := s.agentMgr.CreateIfDead(ctx, s.syncResp, activeInstances); err != nil {
				return err
			}
			s.syncActiveInstances = activeInstances
			return nil
		}

		return s.UpdateIfInstanceChanged(ctx)
	}

	activeInstances, err := s.activeInstancesIfRequired(res.Response)
	if err != nil {
		s.lg.Error("get active instances failed", slogx.Error(err))
	}

	s.lg.Info(
		"strategy changed",
		slog.Int("version", int(res.Response.Version)),
		slog.Int("numItems", res.Response.NumItems(activeInstances)),
	)

	if err := s.agentMgr.Update(ctx, res.Response, activeInstances); err != nil {
		return err
	}
	s.syncResp = res.Response
	s.syncActiveInstances = activeInstances
	return nil
}

func (s *Syncer) UpdateIfInstanceChanged(ctx context.Context) error {
	if s.syncResp == nil || !s.syncResp.HasInstances() {
		return nil
	}

	activeInstances, err := s.tool.GetKvmInstances()
	if err != nil {
		s.lg.Error("get active instances failed", slogx.Error(err))
		return nil
	}

	needUpdate := func() bool {
		for _, strategy := range s.syncResp.Strategy {
			for _, instanceName := range strategy.InstanceNames {
				syncExists := slices.Contains(s.syncActiveInstances, instanceName)
				currExists := slices.Contains(activeInstances, instanceName)
				if syncExists != currExists {
					return true
				}
			}
		}
		return false
	}()
	if !needUpdate {
		return nil
	}

	s.lg.Info(
		"instances changed, will restart agent",
		slog.Int("numItems", s.syncResp.NumItems(activeInstances)),
	)
	if err := s.agentMgr.Update(ctx, s.syncResp, activeInstances); err != nil {
		return err
	}
	s.syncActiveInstances = activeInstances
	return nil
}

func (s *Syncer) activeInstancesIfRequired(resp *SyncStrategyResponse) ([]string, error) {
	if !resp.HasInstances() {
		return nil, nil
	}
	return s.tool.GetKvmInstances()
}

func (s *Syncer) syncMetric(ctx context.Context) error {
	if s.regResp == nil || s.syncResp == nil {
		return nil
	}

	pid, alive := s.agentMgr.Pid()
	if !alive {
		return nil
	}

	metrics := MetricsEntry{
		SamplingTimestamp:      time.Now().Unix(),
		SamplingMicroTimestamp: time.Now().UnixMicro() % 1e6,
		StartTime:              s.agentMgr.StartTime().Unix(),
	}

	err := func() error {
		stats, err := s.agentMgr.CollectStats(ctx)
		if err != nil {
			return err
		}

		for _, task := range stats.Tasks {
			metrics.CapBytes += task.Capture.CapBytes.Bytes
			metrics.CapPackets += task.Capture.CapPackets.Packets
			metrics.CapDrop += task.Capture.DropPackets.Packets
			for _, output := range task.Outputs {
				metrics.FwdBytes += output.FwdBytes.Bytes
				metrics.FwdPackets += output.FwdPackets.Packets
			}
		}
		return nil
	}()
	if err != nil {
		s.lg.Error("agent stats error", slogx.Error(err))
	}

	err = func() error {
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			return errors.Wrapf(err, "new process")
		}

		cpuPercent, err := p.CPUPercentWithContext(ctx)
		if err != nil {
			return errors.Wrapf(err, "get cpu percent")
		}
		cpuCnt, err := cpu.Counts(true)
		if err != nil {
			return errors.Wrapf(err, "get cpu count")
		}
		metrics.CpuLoad = cpuPercent / 100
		metrics.CpuLoadRate = metrics.CpuLoad / float64(cpuCnt)

		processMemory, err := p.MemoryInfoWithContext(ctx)
		if err != nil {
			return errors.Wrapf(err, "get process memory")
		}

		machineMemory, err := mem.VirtualMemoryWithContext(ctx)
		if err != nil {
			return errors.Wrapf(err, "get machine memory")
		}

		metrics.MemUse = processMemory.RSS
		metrics.MemUseRate = float64(metrics.MemUse) / float64(machineMemory.Total)

		return nil
	}()
	if err != nil {
		s.lg.Error("collect system metrics failed", slogx.Error(err))
	}

	return s.client.SyncMetrics(ctx, s.regResp.Id, SyncMetricsRequest{
		Metrics: metrics,
		Logs:    s.logBuf.Clear(),
		Pid:     int32(pid),
	})
}
