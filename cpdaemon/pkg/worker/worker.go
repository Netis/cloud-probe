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
	"github.com/samber/lo"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/cgroup"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

type ExecConfig struct {
	PidFile    string
	Executable string
	Env        map[string]string
	WorkDir    string

	CpuAffinity int
	LogLevel    string
	Control     ControlConfig
	Tasks       []TaskConfig
	ConfigFile  string

	CgroupCfg cgroup.CgroupCfg
	CpuLimit  *float64
	MemLimit  *int64
}

type Worker struct {
	name string
	cfg  ExecConfig
	lg   *slog.Logger

	mu        sync.Mutex
	cmd       *exec.Cmd
	waitDone  chan error
	startTime time.Time
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

func (w *Worker) Start(ctx context.Context) error {
	if err := w.startProcess(); err != nil {
		return err
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				w.lg.Error("recovered", slog.Any("err", r))
			}
		}()

		resLimitCleanup, err := w.createResLimit()
		if err != nil {
			w.lg.Error("create resource limit failed, stopping worker", slogx.Error(err))
			w.Stop()
		}

		pidCleanup := w.createPidFile()

		err = w.cmd.Wait()
		if err != nil {
			w.lg.Error("process exited with error", slogx.Error(err))
		} else {
			w.lg.Info("process exited")
		}
		w.waitDone <- err
		close(w.waitDone)

		if resLimitCleanup != nil {
			if err := resLimitCleanup(); err != nil {
				w.lg.Error("clean resource limit failed", slogx.Error(err))
			} else {
				w.lg.Info("clean resource limit success")
			}
		}
		if pidCleanup != nil {
			pidCleanup()
		}

		w.mu.Lock()
		w.cmd = nil
		w.mu.Unlock()
		w.lg.Info("worker exited")
	}()

	return nil
}

func (w *Worker) startProcess() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cmd != nil {
		return errors.Errorf("worker %s is already running", w.name)
	}

	if err := w.writeConfig(); err != nil {
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

	w.cmd = cmd
	w.waitDone = make(chan error, 1)
	w.startTime = time.Now()
	return nil
}

func (w *Worker) Stop() error {
	w.mu.Lock()
	cmd := w.cmd
	w.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
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
	return nil
}

func (w *Worker) createResLimit() (func() error, error) {
	if w.cfg.CpuLimit == nil || *w.cfg.CpuLimit <= 0 {
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
			CpuLimit: w.cfg.CpuLimit,
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

func (w *Worker) writeConfig() error {
	fp, err := os.Create(w.cfg.ConfigFile)
	if err != nil {
		return errors.Wrapf(err, "create worker config file: %s", w.cfg.ConfigFile)
	}
	defer fp.Close()

	cfg := Config{
		LogLevel: w.cfg.LogLevel,
		Control:  w.cfg.Control,
		Tasks:    w.cfg.Tasks,
	}
	if w.cfg.CpuAffinity >= 0 {
		cfg.CpuAffinity = lo.ToPtr(w.cfg.CpuAffinity)
	}

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
