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

	"github.com/Netis/cloud-probe/cpdaemon/pkg/agent"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/slogx"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/version"
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
	AgentCfg         agent.AgentConfig
	RegCfg           RegConfig
	RegRetryInterval time.Duration
	SyncInterval     time.Duration
	TasksFile        string
}

type Syncer struct {
	agentMgr *AgentManager
	client   *HttpClient
	cfg      SyncerConfig
	lg       *slog.Logger

	daemonUUID        string
	startTime         time.Time
	networkInterfaces []NicEntry

	regResp             *RegisterResponse
	syncResp            *SyncStrategyResponse
	syncActiveInstances []string
}

func NewSyncer(client *HttpClient, cfg SyncerConfig) (*Syncer, error) {
	if err := cfg.RegCfg.Validate(); err != nil {
		return nil, err
	}

	s := &Syncer{
		agentMgr: NewAgentManager(cfg.AgentCfg, cfg.TasksFile),
		client:   client,
		cfg:      cfg,
		lg:       slog.Default().With(slogx.LoggerName("cpm.syncer")),

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
	tm := time.NewTimer(0)
	defer tm.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tm.C:
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
			tm.Reset(s.cfg.SyncInterval)
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
	if s.syncResp == nil {
		return nil
	}
	if !s.syncResp.HasInstances() {
		return nil
	}

	activeInstances, err := s.activeInstances()
	if err != nil {
		s.lg.Error("get active instances failed", slogx.Error(err))
		return nil
	}

	needUpdate := false
	for _, strategy := range s.syncResp.Strategy {
		for _, instanceName := range strategy.InstanceNames {
			syncExists := slices.Contains(s.syncActiveInstances, instanceName)
			currExists := slices.Contains(activeInstances, instanceName)
			if syncExists != currExists {
				needUpdate = true
				break
			}
		}
		if needUpdate {
			break
		}
	}
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
	return s.activeInstances()
}

func (s *Syncer) activeInstances() ([]string, error) {
	// TODO:
	return nil, nil
}
