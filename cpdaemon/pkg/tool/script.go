package tool

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
)

func RunShellScript(scriptFile string, arg ...string) (string, error) {
	args := append([]string{scriptFile}, arg...)
	cmd := exec.Command("sh", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return "", errors.Wrapf(err, "command failed: %s", strings.TrimSpace(stderr.String()))
		} else {
			return "", errors.Wrapf(err, "system error")
		}
	}
	if stdout.Len() == 0 && stderr.Len() > 0 {
		return "", errors.Errorf("command failed: %s", strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
