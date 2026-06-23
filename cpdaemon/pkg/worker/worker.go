package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/cgroup"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

type ResLimit struct {
	Cpu *float64
	Mem *int64
}

type ExecConfig struct {
	PidFile    string
	Executable string
	Env        map[string]string
	WorkDir    string
	ConfigFile string
	CgroupCfg  cgroup.CgroupCfg
}

type Worker struct {
	name string
	cfg  ExecConfig
	lg   *slog.Logger

	mu        sync.Mutex
	cmd       *exec.Cmd
	waitDone  chan error
	startTime time.Time
	resLimit  *cgroup.ProcessLimit
}

func NewWorker(name string, cfg ExecConfig) (*Worker, error) {
	return &Worker{
		name: name,
		cfg:  cfg,
		lg:   slog.Default().With(slogx.LoggerName("worker"), slog.String("name", name)),
	}, nil
}

func (w *Worker) SetLogger(lg *slog.Logger) {
	w.lg = lg.With(slogx.LoggerName("worker"), slog.String("name", w.name))
}

func (w *Worker) StartTime() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.startTime
}

func (w *Worker) Pid() int {
	w.mu.Lock()
	cmd := w.cmd
	w.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return 0
	}
	return cmd.Process.Pid
}

func (w *Worker) IsAlive(ctx context.Context) (bool, error) {
	w.mu.Lock()
	cmd := w.cmd
	w.mu.Unlock()

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

func (w *Worker) Start(ctx context.Context, wCfg *Config) error {
	err := func() error {
		w.mu.Lock()
		defer w.mu.Unlock()

		if err := w.startProcess(wCfg); err != nil {
			return err
		}
		return nil
	}()
	if err != nil {
		return err
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				w.lg.Error("recovered", slog.Any("err", r))
			}
		}()

		pidCleanup := w.createPidFile()

		err = w.cmd.Wait()
		if err != nil {
			w.lg.Error("process exited with error", slogx.Error(err))
		} else {
			w.lg.Info("process exited")
		}
		w.waitDone <- err
		close(w.waitDone)

		w.mu.Lock()
		w.cmd = nil
		resLimit := w.resLimit
		w.mu.Unlock()

		if resLimit != nil {
			if err := resLimit.Cleanup(); err != nil {
				w.lg.Error("clean resource limit failed", slogx.Error(err))
			} else {
				w.lg.Info("clean resource limit success")
			}
		}

		if pidCleanup != nil {
			pidCleanup()
		}
		w.lg.Info("worker exited")
	}()

	return nil
}

func (w *Worker) startProcess(wCfg *Config) error {
	if w.cmd != nil {
		return errors.Errorf("worker %s is already running", w.name)
	}

	if err := w.writeConfig(wCfg); err != nil {
		return err
	}

	args := []string{"-c", w.cfg.ConfigFile}
	cmd := exec.Command(w.cfg.Executable, args...)
	cmd.Env = os.Environ()
	for k, v := range w.cfg.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	cmd.Dir = w.cfg.WorkDir
	cmd.Stderr = newPipeWriter(newSlogOutput(w.lg))
	cmd.Stdout = newPipeWriter(newSlogOutput(w.lg))

	if err := cmd.Start(); err != nil {
		return errors.Wrapf(err, "start worker %s failed", w.name)
	}

	w.lg.Info(
		"worker started",
		slog.Int("pid", cmd.Process.Pid),
		slog.String("command", strings.Join(cmd.Args, " ")),
	)

	cfgStr, _ := json.Marshal(wCfg)
	w.lg.Info("worker config", slog.String("config", string(cfgStr)))

	w.cmd = cmd
	w.waitDone = make(chan error, 1)
	w.startTime = time.Now()
	return nil
}

func (w *Worker) Stop() error {
	w.mu.Lock()
	cmd := w.cmd
	w.mu.Unlock()

	w.stopProcess(cmd)
	return nil
}

func (w *Worker) stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	w.lg.Info("stopping worker, send SIGINT", slog.Int("pid", cmd.Process.Pid))

	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		if !errors.Is(err, os.ErrProcessDone) {
			w.lg.Error("SIGINT failed", slogx.Error(err))
		}
	}

	killTimeout := 10 * time.Second
	select {
	case <-w.waitDone:
	case <-time.After(killTimeout):
		w.lg.Info("forcing kill after timeout", slog.String("timeout", killTimeout.String()))
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			w.lg.Error("force kill failed", slogx.Error(err))
		}

		select {
		case <-w.waitDone:
		case <-time.After(1 * time.Second):
			w.lg.Error("wait timeout after force kill")
		}
	}
}

func (w *Worker) UpdateResLimit(resLimit ResLimit) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if resLimit.Cpu == nil || *resLimit.Cpu <= 0 {
		// The worker is still running and remains a member of its cgroup, so we
		// cannot rmdir it here (it would fail with EBUSY). Reset the quota to
		// unlimited instead; the cgroup directory is removed when the worker
		// exits (see Cleanup in Start). We keep w.resLimit so that exit cleanup
		// still runs.
		if w.resLimit != nil {
			w.lg.Info("clearing previous cpu limit")
			if err := w.resLimit.Reset(); err != nil {
				return errors.WithMessage(err, "clear previous cpu limit failed")
			}
		}
		return nil
	}

	handle, err := w.createResLimit(resLimit)
	if err != nil {
		return errors.WithMessage(err, "create cpu limit failed")
	}
	w.resLimit = handle
	return nil
}

func (w *Worker) createResLimit(resLimit ResLimit) (*cgroup.ProcessLimit, error) {
	if resLimit.Cpu == nil || *resLimit.Cpu <= 0 {
		w.lg.Info("cpu limit is not set, skip create cgroup")
		return nil, nil
	}

	cmd := w.cmd
	if cmd == nil || cmd.Process == nil {
		// never happen
		w.lg.Error("worker is not running, skip create cgroup")
		return nil, nil
	}
	return CreateProcessResLimit(
		cmd.Process.Pid,
		ResLimitCfg{
			CgroupCfg: w.cfg.CgroupCfg,
		},
		ResLimitQuota{
			CpuLimit: resLimit.Cpu,
		},
	)
}

func (w *Worker) createPidFile() func() error {
	if w.cfg.PidFile == "" {
		w.lg.Info("pidFile not set, skip create pid file")
		return nil
	}
	cmd := w.cmd
	if cmd == nil || cmd.Process == nil {
		// never happen
		w.lg.Error("worker is not running, skip create pidFile")
		return nil
	}
	err := os.WriteFile(w.cfg.PidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
	if err != nil {
		w.lg.Error("create pid file error", slog.String("file", w.cfg.PidFile))
		return nil
	}
	w.lg.Info("create pid file success", slog.String("file", w.cfg.PidFile))
	return func() error {
		if err := os.Remove(w.cfg.PidFile); err != nil {
			w.lg.Error("remove pid file error", slog.String("file", w.cfg.PidFile))
		}
		return nil
	}
}

func (w *Worker) UpdateConfig(cfg *Config) error {
	return w.writeConfig(cfg)
}

func (w *Worker) writeConfig(cfg *Config) error {
	fp, err := os.Create(w.cfg.ConfigFile)
	if err != nil {
		return errors.Wrapf(err, "create worker config file: %s", w.cfg.ConfigFile)
	}
	defer fp.Close()

	enc := json.NewEncoder(fp)
	enc.SetIndent("", "    ")
	if err := enc.Encode(cfg); err != nil {
		return errors.Wrapf(err, "create worker config file: %s", w.cfg.ConfigFile)
	}

	if err := fp.Close(); err != nil {
		return errors.Wrapf(err, "create worker config file: %s", w.cfg.ConfigFile)
	}
	return nil
}

func (w *Worker) ReloadConfig(ctx context.Context) error {
	w.mu.Lock()
	cmd := w.cmd
	w.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	w.lg.Info("reloading worker config, send SIGHUP", slog.Int("pid", cmd.Process.Pid))

	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		return errors.Wrapf(err, "send SIGHUP to worker failed, pid=%d", cmd.Process.Pid)
	}
	return nil
}
