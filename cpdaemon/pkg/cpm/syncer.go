package cpm

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/tool"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/version"
	"github.com/Netis/cloud-probe/cpgolib/cpworker"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

type RegConfig struct {
	Name          string
	NodeName      string
	PlatformId    string
	DeployEnv     string
	Labels        []string
	IncludingNICs []string

	PodName   string
	Namespace string

	UuidFile string
	UuidGen  UuidGenConfig
}

func (c *RegConfig) Validate() error {
	if c.Name == "" {
		return errors.New("name is required")
	}
	if c.UuidFile == "" {
		return errors.New("uuid_file is required")
	}
	if c.PlatformId == "" {
		return errors.New("platform_id is required")
	}
	if !slices.Contains([]string{DeployEnv_INSTANCE, DeployEnv_HOST}, c.DeployEnv) {
		return errors.Errorf("deploy_env must be %s or %s", DeployEnv_INSTANCE, DeployEnv_HOST)
	}
	return nil
}

type SyncerConfig struct {
	RegCfg                         RegConfig
	RegRetryInterval               time.Duration
	SyncStrategyInterval           time.Duration
	SyncStrategyMaxRetries         int
	SyncMetricInterval             time.Duration
	StopWorkerAfterRegFailMuinutes int
}

type Tool interface {
	GetContainerHostPid(containerId string) (int, error)
	GetKvmInstances() ([]string, error)
	GetKvmInstanceNics(instanceName string) ([]string, error)
}

type IWorkerManager interface {
	CreateIfDead(ctx context.Context, resp *SyncStrategyResponse, daemonUUID string, activeInstances []string) error
	Update(ctx context.Context, resp *SyncStrategyResponse, daemonUUID string, activeInstances []string) error
	Stop() error
	IsAlive(ctx context.Context) (bool, error)
	StartTime() time.Time
	Pid() int
	BuffSizePerTask() uint64
	CollectStatsSummary(ctx context.Context) (cpworker.StatsSummary, error)
	SetLogger(lg *slog.Logger)
}

type Client interface {
	Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error)
	SyncStrategy(ctx context.Context, daemonId int64, version int32) (*SyncStrategyResult, error)
	SyncMetrics(ctx context.Context, daemonId int64, req SyncMetricsRequest) error
}

type Syncer struct {
	client    Client
	workerMgr IWorkerManager
	tool      Tool
	cfg       SyncerConfig

	daemonUUID        string
	startTime         time.Time
	networkInterfaces []NicEntry

	regResp             *RegisterResponse
	syncResp            *SyncStrategyResponse
	syncActiveInstances []string

	logBuf *SyncLogBuffer
	lg     *slog.Logger
}

func killOrphanWorker(workerCfg WorkerConfig) error {
	if workerCfg.PidFile == "" {
		return nil
	}
	data, err := os.ReadFile(workerCfg.PidFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return errors.WithStack(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return errors.WithStack(err)
	}
	p, err := process.NewProcess(int32(pid))
	switch {
	case errors.Is(err, process.ErrorProcessNotRunning):
		return nil
	case err != nil:
		return errors.WithStack(err)
	}
	cmdLineSlice, err := p.CmdlineSlice()
	if err != nil {
		return errors.WithStack(err)
	}
	if len(cmdLineSlice) == 0 {
		return errors.Errorf("unexpected command line: %s", strings.Join(cmdLineSlice, " "))
	}
	if cmdLineSlice[0] != workerCfg.Executable {
		return errors.Errorf("unexpected command line: %s", strings.Join(cmdLineSlice, " "))
	}

	slog.Default().Info(
		"kill orphan worker",
		slog.Int("pid", pid),
		slog.String("cmdline", strings.Join(cmdLineSlice, " ")),
	)
	if err := p.Kill(); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func NewSyncer(
	client *HttpClient,
	workerCfg WorkerConfig,
	tool tool.Tool,
	cfg SyncerConfig,
) (*Syncer, error) {
	if err := cfg.RegCfg.Validate(); err != nil {
		return nil, err
	}
	if err := workerCfg.Validate(); err != nil {
		return nil, err
	}

	// 只有在 cpdaemon 被kill时才会出现这种情况
	if err := killOrphanWorker(workerCfg); err != nil {
		return nil, errors.Wrap(err, "kill orphan worker error")
	}

	workerMgr := NewWorkerManager(workerCfg, tool)
	return newSyncer(client, workerMgr, tool, cfg)
}

func newSyncer(
	client Client,
	workerMgr IWorkerManager,
	tool Tool,
	cfg SyncerConfig,
) (*Syncer, error) {
	logBuf := &SyncLogBuffer{}
	lg := slog.New(slogx.Multiple(
		slog.Default().Handler(),
		&SyncLogHandler{w: logBuf, level: slog.LevelDebug},
	))
	workerMgr.SetLogger(lg)

	s := &Syncer{
		client:    client,
		workerMgr: workerMgr,
		tool:      tool,
		cfg:       cfg,

		logBuf: logBuf,
		lg:     lg.With(slogx.LoggerName("cpm.syncer")),

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
		uuidVal, err := s.cfg.RegCfg.UuidGen.Generate()
		if err != nil {
			return err
		}
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

	uuidVal, err = s.cfg.RegCfg.UuidGen.Generate()
	if err != nil {
		return err
	}
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
			Index:         intf.Index,
			Name:          intf.Name,
			Mac:           intf.HardwareAddr.String(),
			Flags:         int(intf.Flags),
			Mtu:           intf.MTU,
			InetAddresses: []string{}, // 不能为nil，可以为空数组
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
			// unreachable
			panic(err)
		}

		err = s.syncLoop(ctx)
		switch {
		case errors.Is(err, context.Canceled):
			return nil
		case err != nil:
			s.lg.Error("sync loop error, will re-register", slogx.Error(err))
		}
	}
}

func (s *Syncer) registerLoop(ctx context.Context) error {
	tm := time.NewTimer(0)
	defer tm.Stop()

	mins := s.cfg.StopWorkerAfterRegFailMuinutes
	startTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tm.C:
			lg := s.lg.With(
				slog.String("pa_uuid", s.daemonUUID),
				slog.String("name", s.cfg.RegCfg.Name),
				slog.String("node_name", s.cfg.RegCfg.NodeName),
				slog.String("pod_name", s.cfg.RegCfg.PodName),
				slog.String("platform_id", s.cfg.RegCfg.PlatformId),
			)

			err := s.doRegister(ctx)
			if err == nil {
				lg.Info("register success", slog.Int64("daemonId", s.regResp.Id))
				return nil
			}

			if s.syncResp != nil && mins >= 0 && time.Since(startTime) > time.Duration(mins)*time.Minute {
				lg.Info("stop worker after register failed for a long time")
				if err := s.workerMgr.Stop(); err != nil {
					s.lg.Error("stop worker failed", slogx.Error(err))
				} else {
					s.syncResp = nil
				}
			}

			lg.Error("register loop error, will retry", slogx.Error(err))
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
			return LabelEntry{Value: label}
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

func (s *Syncer) syncLoop(ctx context.Context) error {
	strategyTimer := time.NewTimer(0)
	defer strategyTimer.Stop()

	metricTimer := time.NewTimer(s.cfg.SyncMetricInterval)
	defer metricTimer.Stop()

	syncStrategyFailCount := 0
	for {
		select {
		case <-ctx.Done():
			if err := s.workerMgr.Stop(); err != nil {
				s.lg.Error("stop worker failed", slogx.Error(err))
			}
			return ctx.Err()
		case <-strategyTimer.C:
			var lastVersion int32
			if s.syncResp != nil {
				lastVersion = s.syncResp.Version
			}

			res, err := s.client.SyncStrategy(ctx, s.regResp.Id, lastVersion)
			if err != nil {
				if syncStrategyFailCount >= s.cfg.SyncStrategyMaxRetries {
					return err
				}
				syncStrategyFailCount++
				s.lg.Error(
					"sync strategy failed, will retry",
					slog.Int("fail_count", syncStrategyFailCount),
					slogx.Error(err),
				)
			} else {
				syncStrategyFailCount = 0
				if err := s.applyStrategy(ctx, res); err != nil {
					s.lg.Error("apply strategy failed", slogx.Error(err))
				}
			}

			strategyTimer.Reset(s.cfg.SyncStrategyInterval)
		case <-metricTimer.C:
			s.syncMetric(ctx)
			metricTimer.Reset(s.cfg.SyncMetricInterval)
		}
	}
}

func (s *Syncer) applyStrategy(ctx context.Context, res *SyncStrategyResult) error {
	if !res.Changed {
		s.lg.Info("strategy unchanged")
		alive, err := s.workerMgr.IsAlive(ctx)
		if err != nil {
			s.lg.Info("worker check alive failed", slogx.Error(err))
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
				"worker is not alive, will restart",
				slog.Int("numItems", numItems),
			)

			if err := s.workerMgr.CreateIfDead(ctx, s.syncResp, s.daemonUUID, activeInstances); err != nil {
				return err
			}
			s.syncActiveInstances = activeInstances
			return nil
		}

		return s.updateIfInstanceChanged(ctx)
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

	if err := s.workerMgr.Update(ctx, res.Response, s.daemonUUID, activeInstances); err != nil {
		return err
	}
	s.syncResp = res.Response
	s.syncActiveInstances = activeInstances
	return nil
}

func (s *Syncer) updateIfInstanceChanged(ctx context.Context) error {
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
		"instances changed, will restart worker",
		slog.Int("numItems", s.syncResp.NumItems(activeInstances)),
	)
	if err := s.workerMgr.Update(ctx, s.syncResp, s.daemonUUID, activeInstances); err != nil {
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

func (s *Syncer) syncMetric(ctx context.Context) {
	if s.regResp == nil {
		return
	}

	var durStats struct {
		worker time.Duration
		system time.Duration
		sync   time.Duration
	}

	var req SyncMetricsRequest

	begin := time.Now()
	isAlive, err := s.workerMgr.IsAlive(ctx)
	if err != nil {
		s.lg.Error("check worker alive failed", slogx.Error(err))
	}
	if isAlive {
		pid := s.workerMgr.Pid()
		buffSizePerTask := s.workerMgr.BuffSizePerTask()

		metrics := MetricsEntry{
			SamplingTimestamp:      time.Now().Unix(),
			SamplingMicroTimestamp: time.Now().UnixMicro() % 1e6,
			CapBuff:                buffSizePerTask,
		}
		workerBegin := time.Now()
		if err := s.collectTaskStats(ctx, &metrics); err != nil {
			s.lg.Error("collect cpworker stats error", slogx.Error(err))
		}
		durStats.worker = time.Since(workerBegin)

		systemBegin := time.Now()
		if err := s.collectSysStats(ctx, int32(pid), &metrics); err != nil {
			s.lg.Error("collect system metrics failed", slogx.Error(err))
		}
		durStats.system = time.Since(systemBegin)

		req.Metrics = &metrics

		// 不上报 pid 表示: 未捕获状态
		req.Pid = lo.ToPtr(int32(pid))
	}

	logs := s.logBuf.Clear()
	if logs == nil {
		logs = []LogEntry{}
	}
	req.Logs = logs

	syncBegin := time.Now()
	err = s.client.SyncMetrics(ctx, s.regResp.Id, req)
	if err != nil {
		s.lg.Error("send metrics to cpm error", slogx.Error(err))
	}
	durStats.sync = time.Since(syncBegin)

	s.lg.Info(
		"sync metrics finished",
		slog.String("total_dur", time.Since(begin).String()),
		slog.String("worker_dur", durStats.worker.String()),
		slog.String("system_dur", durStats.system.String()),
		slog.String("sync_dur", durStats.sync.String()),
	)
}

func (s *Syncer) collectTaskStats(ctx context.Context, metrics *MetricsEntry) error {
	metrics.StartTime = s.workerMgr.StartTime().Unix()

	stats, err := s.workerMgr.CollectStatsSummary(ctx)
	if err != nil {
		return err
	}

	// WARN: 存在溢出问题，需要CPM端配合处理
	metrics.CapBytes += stats.Capture.CapBytes.Bytes
	metrics.CapPackets += stats.Capture.CapPackets.Packets
	metrics.CapDrop += stats.Capture.DropPackets.Packets
	metrics.FwdBytes += stats.Output.FwdBytes.Bytes
	metrics.FwdPackets += stats.Output.FwdPackets.Packets
	return nil
}

func (s *Syncer) collectSysStats(ctx context.Context, pid int32, metrics *MetricsEntry) error {
	p, err := process.NewProcess(pid)
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
}
