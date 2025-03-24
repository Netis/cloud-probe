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

type Agent struct {
	Name        string
	Executable  string
	Environment map[string]string
	WorkDir     string

	CpuLimit  *float64
	MemLimit  *int64
	Tasks     []TaskConfig
	TasksFile string

	mu       sync.Mutex
	cmd      *exec.Cmd
	waitDone chan error
}

func (a *Agent) IsAlive(ctx context.Context) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cmd == nil || a.cmd.Process == nil {
		return false, nil
	}

	// 发送SIG0（空信号）不会影响进程，用于检测是否存在
	err := a.cmd.Process.Signal(syscall.Signal(0))

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
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cmd != nil {
		return errors.Errorf("agent %s is already running", a.Name)
	}

	if err := a.writeTasks(); err != nil {
		return err
	}

	args := []string{
		"--tasks", a.TasksFile,
	}
	cmd := exec.Command(a.Executable, args...)
	cmd.Env = os.Environ()
	for k, v := range a.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Dir = a.WorkDir

	if err := cmd.Start(); err != nil {
		return errors.Wrapf(err, "start agent %s failed", a.Name)
	}

	a.cmd = cmd
	a.waitDone = make(chan error, 1)

	go func() {
		lg := slog.Default().With(slogx.LoggerName("agent")).With(slog.String("name", a.Name))
		err := cmd.Wait()
		if err != nil {
			lg.Error("process exited with error", slogx.Error(err))
		}
		a.waitDone <- err
		close(a.waitDone)

		a.mu.Lock()
		a.cmd = nil
		a.mu.Unlock()

		if err := a.clean(); err != nil {
			lg.Error("clean failed", slogx.Error(err))
		}
	}()

	return nil
}

func (a *Agent) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cmd == nil || a.cmd.Process == nil {
		return nil
	}

	lg := slog.Default().With(slogx.LoggerName("agent")).With(slog.String("name", a.Name))

	if err := a.cmd.Process.Signal(syscall.SIGINT); err != nil {
		if !errors.Is(err, os.ErrProcessDone) {
			lg.Error("SIGINT failed", slogx.Error(err))
		}
	}

	select {
	case <-a.waitDone:
	case <-time.After(5 * time.Second):
		lg.Info("forcing kill after timeout")
		if err := a.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			lg.Error("kill failed", slogx.Error(err))
		}

		select {
		case <-a.waitDone:
		case <-time.After(1 * time.Second):
			lg.Error("wait timed out after kill")
		}
	}

	a.cmd = nil
	return nil
}

func (a *Agent) clean() error {
	return nil
}

func (a *Agent) writeTasks() error {
	fp, err := os.Create(a.TasksFile)
	if err != nil {
		return errors.Wrapf(err, "create tasks file: %s", a.TasksFile)
	}
	defer fp.Close()

	cfg := struct {
		Tasks []TaskConfig `json:"tasks"`
	}{
		Tasks: a.Tasks,
	}

	if err := json.NewEncoder(fp).Encode(cfg); err != nil {
		return errors.Wrapf(err, "marshal tasks error")
	}

	if err := fp.Close(); err != nil {
		return errors.Wrapf(err, "close tasks file: %s", a.TasksFile)
	}
	return nil
}
