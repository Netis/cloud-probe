package kvm

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
)

type VirshCmdExecutor struct {
	ListNameScript      string
	ListInterfaceScript string
}

func (e *VirshCmdExecutor) ListNames() ([]string, error) {
	var cmd *exec.Cmd
	if e.ListNameScript == "" {
		cmd = exec.Command("sh", "-c", "virsh list | awk 'NR>2 {print $2}'")
	} else {
		cmd = exec.Command("sh", e.ListNameScript)
	}

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

	var result []string
	for line := range strings.Lines(stdout.String()) {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result, nil
}

func (e *VirshCmdExecutor) ListInterfaces(vmName string) ([]string, error) {
	var cmd *exec.Cmd
	if e.ListInterfaceScript == "" {
		cmd = exec.Command("sh", "-c", fmt.Sprintf("virsh domiflist %s | awk 'NR==3 {print $1}'", vmName))
	} else {
		cmd = exec.Command("sh", e.ListInterfaceScript, vmName)
	}

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

	var result []string
	for line := range strings.Lines(stdout.String()) {
		line = strings.TrimSpace(line)
		if line != "" && line != "-" {
			result = append(result, line)
		}
	}
	return result, nil
}
