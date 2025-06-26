package tool

import (
	"bytes"
	"os/exec"

	"github.com/pkg/errors"
)

func GetContainerHostPidByCrictl(containerId string) (int, error) {
	cmd := exec.Command("crictl", "inspect", "-o", "go-template", "--template", "{{.info.pid}}", containerId)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return 0, errors.Wrapf(
			err,
			"crictl inspect failed, stdout: %s, stderr: %s",
			stdout.String(),
			stderr.String(),
		)
	}
	return parsePID(stdout.String())
}
