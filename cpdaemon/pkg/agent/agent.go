package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/samber/lo"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/cgroup"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

type AgentRunTimeConfig struct {
	Executable string
	Env        map[string]string
	WorkDir    string

	CpuAffinity int          `json:"cpu_affinity,omitempty"`
	LogLevel    string       `json:"log_level"`
	UnixSocket  string       `json:"unix_socket"`
	Tasks       []TaskConfig `json:"tasks"`
	ConfigFile  string

	CgroupCfg cgroup.CgroupCfg
	CpuLimit  *float64
	MemLimit  *int64
}

type Agent struct {
	name string
	cfg  AgentRunTimeConfig
	lg   *slog.Logger

	mu        sync.Mutex
	cmd       *exec.Cmd
	waitDone  chan error
	startTime time.Time
}

func NewAgent(name string, cfg AgentRunTimeConfig) (*Agent, error) {
	return &Agent{
		name: name,
		cfg:  cfg,
		lg:   slog.Default().With(slogx.LoggerName("agent"), slog.String("name", name)),
	}, nil
}

func (a *Agent) SetLogger(lg *slog.Logger) {
	a.lg = lg
}

func (a *Agent) StartTime() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.startTime
}

func (a *Agent) Pid() (int, bool) {
	a.mu.Lock()
	cmd := a.cmd
	a.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return 0, false
	}
	return cmd.Process.Pid, true
}

func (a *Agent) IsAlive(ctx context.Context) (bool, error) {
	a.mu.Lock()
	cmd := a.cmd
	a.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return false, nil
	}

	// 发送SIG0（空信号）不会影响进程，用于检测是否存在
	err := cmd.Process.Signal(syscall.Signal(0))

	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrProcessDone):
		return false, nil
	default:
		return false, errors.Wrap(err, "ambiguous process status")
	}
}

func (a *Agent) Start(ctx context.Context) error {
	if err := a.startProcess(); err != nil {
		return err
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				a.lg.Error("recovered", slog.Any("err", r))
			}
		}()

		cleanup, err := a.createResLimit()
		if err != nil {
			a.lg.Error("create resource limit failed, stopping agent", slogx.Error(err))
			a.Stop()
		}

		err = a.cmd.Wait()
		if err != nil {
			a.lg.Error("process exited with error", slogx.Error(err))
		} else {
			a.lg.Info("process exited")
		}
		a.waitDone <- err
		close(a.waitDone)

		if cleanup != nil {
			if err := cleanup(); err != nil {
				a.lg.Error("clean resource limit failed", slogx.Error(err))
			} else {
				a.lg.Info("clean resource limit success")
			}
		}

		a.mu.Lock()
		a.cmd = nil
		a.mu.Unlock()
		a.lg.Info("agent exited")
	}()

	return nil
}

func (a *Agent) startProcess() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cmd != nil {
		return errors.Errorf("agent %s is already running", a.name)
	}

	if err := a.writeConfig(); err != nil {
		return err
	}

	args := []string{"-c", a.cfg.ConfigFile}
	cmd := exec.Command(a.cfg.Executable, args...)
	cmd.Env = os.Environ()
	for k, v := range a.cfg.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Dir = a.cfg.WorkDir
	cmd.Stderr = os.Stdout
	cmd.Stdout = os.Stdout

	if err := cmd.Start(); err != nil {
		return errors.Wrapf(err, "start agent %s failed", a.name)
	}

	a.lg.Info(
		"agent started",
		slog.Int("pid", cmd.Process.Pid),
		slog.String("command", strings.Join(cmd.Args, " ")),
	)

	a.cmd = cmd
	a.waitDone = make(chan error, 1)
	a.startTime = time.Now()
	return nil
}

func (a *Agent) Stop() error {
	a.mu.Lock()
	cmd := a.cmd
	a.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	a.lg.Info("stopping agent, send SIGINT", slog.Int("pid", cmd.Process.Pid))

	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		if !errors.Is(err, os.ErrProcessDone) {
			a.lg.Error("SIGINT failed", slogx.Error(err))
		}
	}

	select {
	case <-a.waitDone:
	case <-time.After(5 * time.Second):
		a.lg.Info("forcing kill after timeout")
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			a.lg.Error("kill failed", slogx.Error(err))
		}

		select {
		case <-a.waitDone:
		case <-time.After(1 * time.Second):
			a.lg.Error("wait timed out after kill")
		}
	}
	return nil
}

func (a *Agent) createResLimit() (func() error, error) {
	if a.cfg.CpuLimit == nil || *a.cfg.CpuLimit <= 0 {
		a.lg.Info("cpu limit is not set, skip cgroup")
		return nil, nil
	}

	cmd := a.cmd
	if cmd == nil || cmd.Process == nil {
		// never happen
		a.lg.Error("agent is not running, skip cgroup")
		return nil, nil
	}
	return CreateProcessResLimit(
		cmd.Process.Pid,
		ResLimitCfg{
			CgroupCfg: a.cfg.CgroupCfg,
		},
		ResLimitQuota{
			CpuLimit: a.cfg.CpuLimit,
		},
	)
}

func (a *Agent) writeConfig() error {
	fp, err := os.Create(a.cfg.ConfigFile)
	if err != nil {
		return errors.Wrapf(err, "create agent config file: %s", a.cfg.ConfigFile)
	}
	defer fp.Close()

	cfg := Config{
		LogLevel:   a.cfg.LogLevel,
		UnixSocket: a.cfg.UnixSocket,
		Tasks:      a.cfg.Tasks,
	}
	if a.cfg.CpuAffinity >= 0 {
		cfg.CpuAffinity = lo.ToPtr(a.cfg.CpuAffinity)
	}

	enc := json.NewEncoder(fp)
	enc.SetIndent("", "    ")
	if err := enc.Encode(cfg); err != nil {
		return errors.Wrapf(err, "marshal tasks error")
	}

	if err := fp.Close(); err != nil {
		return errors.Wrapf(err, "close agent config file: %s", a.cfg.ConfigFile)
	}
	return nil
}
