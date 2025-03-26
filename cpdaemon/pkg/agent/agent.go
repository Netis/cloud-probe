package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/slogx"
)

type AgentRunTimeConfig struct {
	Executable string
	Env        map[string]string
	WorkDir    string

	CgroupVersion   string
	CgroupRoot      string
	CgroupHierarchy string

	TasksFile string
	Tasks     []TaskConfig

	CpuLimit *float64
	MemLimit *int64
}

type Agent struct {
	name string
	cfg  AgentRunTimeConfig
	lg   *slog.Logger

	mu       sync.Mutex
	cmd      *exec.Cmd
	waitDone chan error
}

func NewAgent(name string, cfg AgentRunTimeConfig) (*Agent, error) {
	return &Agent{
		name: name,
		cfg:  cfg,
		lg:   slog.Default().With(slogx.LoggerName("agent")).With(slog.String("name", name)),
	}, nil
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
	a.lg.Info("agent started")

	go func() {
		cleanCgroup, err := a.createCgroup()
		if err != nil {
			a.lg.Error("create cgroup failed, stopping agent", slogx.Error(err))
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

		if cleanCgroup != nil {
			if err := cleanCgroup(); err != nil {
				a.lg.Error("clean cgroup failed", slogx.Error(err))
			} else {
				a.lg.Info("clean cgroup success")
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

	if err := a.writeTasks(); err != nil {
		return err
	}

	args := []string{
		"--tasks", a.cfg.TasksFile,
	}
	cmd := exec.Command(a.cfg.Executable, args...)
	cmd.Env = os.Environ()
	for k, v := range a.cfg.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Dir = a.cfg.WorkDir

	if err := cmd.Start(); err != nil {
		return errors.Wrapf(err, "start agent %s failed", a.name)
	}

	a.cmd = cmd
	a.waitDone = make(chan error, 1)
	return nil
}

func (a *Agent) Stop() error {
	a.mu.Lock()
	cmd := a.cmd
	a.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	a.lg.Info("stopping agent, send SIGINT")

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

func (a *Agent) createCgroup() (func() error, error) {
	emptyClean := func() error { return nil }

	if a.cfg.CpuLimit == nil || *a.cfg.CpuLimit <= 0 {
		a.lg.Info("cpu limit is not set, skip cgroup")
		return emptyClean, nil
	}

	cmd := a.cmd
	if cmd == nil || cmd.Process == nil {
		// never happen
		a.lg.Error("agent is not running, skip cgroup")
		return emptyClean, nil
	}

	cgroupName := fmt.Sprintf("pid-%d", cmd.Process.Pid)
	switch a.cfg.CgroupVersion {
	case CgroupVersionV1:
		cgroupPath, err := CreateV1CpuCgroup(a.cfg.CgroupRoot, a.cfg.CgroupHierarchy, cgroupName)
		if err != nil {
			return nil, err
		}
		a.lg.Info("create cgroup", slog.String("cgroupPath", cgroupPath))

		clean := func() error {
			return RemoveCgroup(cgroupPath)
		}

		if err := SetV1CpuQuota(cgroupPath, *a.cfg.CpuLimit); err != nil {
			return clean, err
		}
		if err := AddCgroupProcess(cgroupPath, cmd.Process.Pid); err != nil {
			return clean, err
		}
		return clean, nil
	case CgroupVersionV2:
		cgroupPath, err := CreateV2Cgroup(a.cfg.CgroupRoot, a.cfg.CgroupHierarchy, cgroupName)
		if err != nil {
			return nil, err
		}
		a.lg.Info("create cgroup", slog.String("cgroupPath", cgroupPath))

		clean := func() error {
			return RemoveCgroup(cgroupPath)
		}

		if err := SetV2CpuQuota(cgroupPath, *a.cfg.CpuLimit); err != nil {
			return clean, err
		}
		if err := AddCgroupProcess(cgroupPath, cmd.Process.Pid); err != nil {
			return clean, err
		}
		return clean, nil
	default:
		return nil, errors.Errorf("unknown cgroup version: %s", a.cfg.CgroupVersion)
	}
}

func (a *Agent) writeTasks() error {
	fp, err := os.Create(a.cfg.TasksFile)
	if err != nil {
		return errors.Wrapf(err, "create tasks file: %s", a.cfg.TasksFile)
	}
	defer fp.Close()

	cfg := struct {
		Tasks []TaskConfig `json:"tasks"`
	}{
		Tasks: a.cfg.Tasks,
	}

	if err := json.NewEncoder(fp).Encode(cfg); err != nil {
		return errors.Wrapf(err, "marshal tasks error")
	}

	if err := fp.Close(); err != nil {
		return errors.Wrapf(err, "close tasks file: %s", a.cfg.TasksFile)
	}
	return nil
}
