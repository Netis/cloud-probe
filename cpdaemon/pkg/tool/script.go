package tool

import (
	"bytes"
	"os/exec"

	"github.com/pkg/errors"
)

func RunShellScript(script string, args ...string) (string, error) {
	cmd := exec.Command(script, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", errors.Wrapf(
			err,
			"command failed, stdout: %s, stderr: %s",
			stdout.String(),
			stderr.String(),
		)
	}
	return stdout.String(), nil
}
