package tool

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
)

func GetKvmInstancesByVirsh() ([]string, error) {
	cmd := exec.Command("sh", "-c", "virsh list | awk 'NR>2 {print $2}'")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return nil, errors.Wrapf(err, "command failed: %s", strings.TrimSpace(stderr.String()))
		} else {
			return nil, errors.Wrapf(err, "system error")
		}
	}
	if stdout.Len() == 0 && stderr.Len() > 0 {
		return nil, errors.Errorf("command failed: %s", strings.TrimSpace(stderr.String()))
	}

	return parseKvmInstances(stdout.String())
}

func GetKvmInstanceNicsByVirsh(instanceName string) ([]string, error) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("virsh domiflist %s | awk 'NR==3 {print $1}'", instanceName))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return nil, errors.Wrapf(err, "command failed: %s", strings.TrimSpace(stderr.String()))
		} else {
			return nil, errors.Wrapf(err, "system error")
		}
	}
	if stdout.Len() == 0 && stderr.Len() > 0 {
		return nil, errors.Errorf("command failed: %s", strings.TrimSpace(stderr.String()))
	}

	return parseKvmInstanceNics(stdout.String())
}

func parseKvmInstances(output string) ([]string, error) {
	var result []string
	for line := range strings.Lines(output) {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result, nil
}

func parseKvmInstanceNics(output string) ([]string, error) {
	var result []string
	for line := range strings.Lines(output) {
		line = strings.TrimSpace(line)
		if line != "" && line != "-" {
			result = append(result, line)
		}
	}
	return result, nil
}
