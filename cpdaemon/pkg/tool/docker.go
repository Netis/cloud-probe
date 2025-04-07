package tool

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

func GetContainerHostPidByDocker(containerId string) (int, error) {
	cmd := exec.Command("docker", "inspect", "--format", "{{.State.Pid}}", containerId)

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
	return parsePID(stdout.String())
}

func parsePID(output string) (int, error) {
	output = strings.TrimSpace(output)
	pid, err := strconv.Atoi(output)
	if err != nil || pid <= 0 {
		return 0, errors.Errorf("invalid PID: %s", output)
	}
	return pid, nil
}
