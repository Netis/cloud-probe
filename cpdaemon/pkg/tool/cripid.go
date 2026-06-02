package tool

import (
	"bytes"
	"os/exec"

	"github.com/pkg/errors"
)

func GetContainerHostPidByCriPid(containerId string) (int, error) {
	cmd := exec.Command("cripid", containerId)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return 0, errors.Wrapf(
			err,
			"cripid failed, stdout: %s, stderr: %s",
			stdout.String(),
			stderr.String(),
		)
	}
	return parsePID(stdout.String())
}
