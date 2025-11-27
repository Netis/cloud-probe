package helpers

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// CpworkerRunner manages the cpworker process lifecycle
type CpworkerRunner struct {
	binary     string
	configPath string
	workDir    string
	cmd        *exec.Cmd
	timeout    time.Duration
	stdout     io.Writer
	stderr     io.Writer
}

// NewCpworkerRunner creates a new cpworker process runner
func NewCpworkerRunner(configPath string, timeout time.Duration) (*CpworkerRunner, error) {
	binary := os.Getenv("CPWORKER_BIN")
	if binary == "" {
		return nil, fmt.Errorf("CPWORKER_BIN environment variable not set")
	}

	if _, err := os.Stat(binary); err != nil {
		return nil, fmt.Errorf("cpworker binary not found at %s: %w", binary, err)
	}

	if _, err := os.Stat(configPath); err != nil {
		return nil, fmt.Errorf("config file not found at %s: %w", configPath, err)
	}

	return &CpworkerRunner{
		binary:     binary,
		configPath: configPath,
		timeout:    timeout,
		stdout:     os.Stdout,
		stderr:     os.Stderr,
	}, nil
}

// SetWorkDir sets the working directory for cpworker process
func (r *CpworkerRunner) SetWorkDir(dir string) {
	r.workDir = dir
}

// SetStdout sets the stdout writer for cpworker output
func (r *CpworkerRunner) SetStdout(w io.Writer) {
	r.stdout = w
}

// SetStderr sets the stderr writer for cpworker output
func (r *CpworkerRunner) SetStderr(w io.Writer) {
	r.stderr = w
}

// Start starts the cpworker process
func (r *CpworkerRunner) Start() error {
	r.cmd = exec.Command(r.binary, "-c", r.configPath)

	if r.workDir != "" {
		r.cmd.Dir = r.workDir
	}

	r.cmd.Stdout = r.stdout
	r.cmd.Stderr = r.stderr

	if err := r.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start cpworker: %w", err)
	}

	return nil
}

// Wait waits for cpworker process to complete
func (r *CpworkerRunner) Wait() error {
	if r.cmd == nil || r.cmd.Process == nil {
		return fmt.Errorf("cpworker not started")
	}

	done := make(chan error, 1)
	go func() {
		done <- r.cmd.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(r.timeout):
		// For pcap_file input, cpworker should exit when EOF is reached
		// Give it a grace period to flush output
		time.Sleep(1 * time.Second)
		r.Kill()
		return fmt.Errorf("cpworker timeout after %s", r.timeout)
	}
}

// Stop gracefully stops the cpworker process
func (r *CpworkerRunner) Stop() error {
	if r.cmd == nil || r.cmd.Process == nil {
		return nil
	}

	if err := r.cmd.Process.Signal(os.Interrupt); err != nil {
		return r.Kill()
	}

	done := make(chan error, 1)
	go func() {
		done <- r.cmd.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		return r.Kill()
	}
}

// Kill forcefully terminates the cpworker process
func (r *CpworkerRunner) Kill() error {
	if r.cmd == nil || r.cmd.Process == nil {
		return nil
	}
	return r.cmd.Process.Kill()
}

// WaitForCompletion waits for cpworker to complete or timeout
func (r *CpworkerRunner) WaitForCompletion() error {
	return r.Wait()
}

// Reload triggers an in-place config reload by sending SIGHUP. cpworker re-reads
// the same config path it was started with.
func (r *CpworkerRunner) Reload() error {
	if r.cmd == nil || r.cmd.Process == nil {
		return fmt.Errorf("cpworker not started")
	}
	return r.cmd.Process.Signal(syscall.SIGHUP)
}

// Running reports whether the process is alive (not exited, not a zombie).
// Uses /proc so it is correct even when the child has not been reaped yet.
func (r *CpworkerRunner) Running() bool {
	if r.cmd == nil || r.cmd.Process == nil {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", r.cmd.Process.Pid))
	if err != nil {
		return false // process gone
	}
	// /proc/<pid>/stat: "pid (comm) state ...". comm may contain spaces/parens,
	// so the state char is the second field after the final ')'.
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	return s[i+2] != 'Z' // 'Z' == zombie (exited, not yet reaped)
}
