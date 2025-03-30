package container

import (
	"bytes"
	"os/exec"
	"strconv"

	"github.com/pkg/errors"
)

type ContainerCmdExecutor struct {
	GetHostPidScript string
}

func (e *ContainerCmdExecutor) GetHostPid(containerId string) (int, error) {
	if e.GetHostPidScript != "" {
		return e.getHostPidByScript(containerId, e.GetHostPidScript)
	}

	if pid, err := e.getHostPidByDocker(containerId); err == nil {
		return pid, nil
	}

	if pid, err := e.getHostPidByCrictl(containerId); err == nil {
		return pid, nil
	}

	return 0, errors.Errorf("failed to get host pid for container %s", containerId)
}

func (e *ContainerCmdExecutor) getHostPidByScript(containerId string, script string) (int, error) {
	cmd := exec.Command("sh", script, containerId)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return 0, errors.Wrapf(
			err,
			"run script %s failed, stdout: %s, stderr: %s",
			script,
			string(stdout.Bytes()),
			string(stderr.Bytes()),
		)
	}

	pid, err := parsePID(stdout.Bytes())
	if err != nil {
		return 0, errors.Wrapf(err, "parse script %s stdout failed", script)
	}
	return pid, nil
}

func (e *ContainerCmdExecutor) getHostPidByDocker(containerID string) (int, error) {
	cmd := exec.Command("docker", "inspect", "--format", "{{.State.Pid}}", containerID)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return 0, errors.Wrapf(
			err,
			"docker inspect failed, stdout: %s, stderr: %s",
			string(stdout.Bytes()),
			string(stderr.Bytes()),
		)
	}
	return parsePID(stdout.Bytes())
}

func (e *ContainerCmdExecutor) getHostPidByCrictl(containerID string) (int, error) {
	cmd := exec.Command("crictl", "inspect", "-o", "go-template", "--template", "{{.info.pid}}", containerID)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return 0, errors.Wrapf(
			err,
			"crictl inspect failed, stdout: %s, stderr: %s",
			string(stdout.Bytes()),
			string(stderr.Bytes()),
		)
	}
	return parsePID(stdout.Bytes())
}

func parsePID(output []byte) (int, error) {
	str := string(bytes.TrimSpace(output))
	pid, err := strconv.Atoi(str)
	if err != nil || pid <= 0 {
		return 0, errors.Errorf("invalid PID: %s", str)
	}
	return pid, nil
}
