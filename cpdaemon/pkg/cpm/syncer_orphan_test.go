package cpm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sleeperEnv = "CPM_TEST_SLEEPER"

func TestMain(m *testing.M) {
	if os.Getenv(sleeperEnv) == "1" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// sleeperExecutable is the argv[0] of processes started by startSleeper.
var sleeperExecutable = os.Args[0]

// startSleeper re-executes the test binary as a stand-in process with a known argv[0]
// (system tools such as sleep may rewrite theirs) and reaps it when the test ends.
func startSleeper(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(sleeperExecutable)
	cmd.Env = append(os.Environ(), sleeperEnv+"=1")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// requireFaithfulCmdline skips the test where the OS does not report the stand-in's argv as
// started, e.g. x86_64 under Rosetta, where /proc/<pid>/cmdline is empty or carries a prefix.
func requireFaithfulCmdline(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	p, err := process.NewProcess(int32(cmd.Process.Pid))
	require.NoError(t, err)
	cmdline, err := p.CmdlineSlice()
	require.NoError(t, err)
	if len(cmdline) == 0 || cmdline[0] != sleeperExecutable {
		t.Skipf("process cmdline is not reported faithfully here: %q", cmdline)
	}
}

func writePidFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cpm-worker.pid")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func isRunning(t *testing.T, pid int) bool {
	t.Helper()
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return false
	}
	status, err := p.Status()
	if err != nil {
		return false
	}
	return len(status) == 0 || status[0] != process.Zombie
}

func waitExit(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("process %d was not killed", cmd.Process.Pid)
	}
}

func TestKillOrphanWorker(t *testing.T) {
	t.Run("pid file missing", func(t *testing.T) {
		cfg := WorkerConfig{PidFile: filepath.Join(t.TempDir(), "cpm-worker.pid"), Executable: sleeperExecutable}
		require.NoError(t, killOrphanWorker(cfg))
	})

	t.Run("orphan worker is killed", func(t *testing.T) {
		cmd := startSleeper(t)
		requireFaithfulCmdline(t, cmd)
		cfg := WorkerConfig{PidFile: writePidFile(t, strconv.Itoa(cmd.Process.Pid)), Executable: sleeperExecutable}

		require.NoError(t, killOrphanWorker(cfg))
		waitExit(t, cmd)
	})

	t.Run("trailing newline is accepted", func(t *testing.T) {
		cmd := startSleeper(t)
		requireFaithfulCmdline(t, cmd)
		cfg := WorkerConfig{PidFile: writePidFile(t, strconv.Itoa(cmd.Process.Pid)+"\n"), Executable: sleeperExecutable}

		require.NoError(t, killOrphanWorker(cfg))
		waitExit(t, cmd)
	})

	t.Run("pid reused by a process started after the pid file is ignored", func(t *testing.T) {
		cmd := startSleeper(t)
		path := writePidFile(t, strconv.Itoa(cmd.Process.Pid))
		// The pid file predates the process, as after a reboot or a crash.
		past := time.Now().Add(-time.Hour)
		require.NoError(t, os.Chtimes(path, past, past))
		cfg := WorkerConfig{PidFile: path, Executable: "cpworker"}

		require.NoError(t, killOrphanWorker(cfg))
		assert.True(t, isRunning(t, cmd.Process.Pid), "an unrelated process must not be killed")
	})

	t.Run("unrelated process older than the pid file is still an error", func(t *testing.T) {
		cmd := startSleeper(t)
		cfg := WorkerConfig{PidFile: writePidFile(t, strconv.Itoa(cmd.Process.Pid)), Executable: "cpworker"}

		err := killOrphanWorker(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected command line")
		assert.True(t, isRunning(t, cmd.Process.Pid), "an unrelated process must not be killed")
	})
}
