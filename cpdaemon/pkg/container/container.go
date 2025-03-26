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
		cmd := exec.Command("sh", e.GetHostPidScript, containerId)

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			return 0, errors.Wrapf(
				err,
				"run script %s failed, stdout: %s, stderr: %s",
				e.GetHostPidScript,
				string(stdout.Bytes()),
				string(stderr.Bytes()),
			)
		}

		pid, err := parsePID(stdout.Bytes())
		if err != nil {
			return 0, errors.Wrapf(err, "parse script %s stdout failed", e.GetHostPidScript)
		}
		return pid, nil
	}

	if pid, err := e.getDockerPID(containerId); err == nil {
		return pid, nil
	}

	if pid, err := e.getCrictlPID(containerId); err == nil {
		return pid, nil
	}

	return 0, errors.Errorf("failed to get host pid for container %s", containerId)
}

func (e *ContainerCmdExecutor) getDockerPID(containerID string) (int, error) {
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

func (e *ContainerCmdExecutor) getCrictlPID(containerID string) (int, error) {
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
