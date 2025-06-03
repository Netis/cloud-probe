package tool

import "github.com/pkg/errors"

type Tool struct {
	GetContainerHostPidScript string
	GetKvmInstancesScript     string
	GetKvmInstanceNicsScript  string
}

func (t Tool) GetContainerHostPid(containerId string) (int, error) {
	if pid, err := GetContainerHostPidByDocker(containerId); err == nil {
		return pid, nil
	}

	if pid, err := GetContainerHostPidByCrictl(containerId); err == nil {
		return pid, nil
	}

	if t.GetContainerHostPidScript != "" {
		output, err := RunShellScript(t.GetContainerHostPidScript, containerId)
		if err != nil {
			return 0, err
		}
		return parsePID(output)
	}

	return 0, errors.Errorf("failed to get host pid for container %s", containerId)
}

func (t Tool) GetKvmInstances() ([]string, error) {
	if t.GetKvmInstancesScript != "" {
		output, err := RunShellScript(t.GetKvmInstancesScript)
		if err != nil {
			return nil, err
		}
		return parseKvmInstances(output)
	}

	return GetKvmInstancesByVirsh()
}

func (t Tool) GetKvmInstanceNics(instanceName string) ([]string, error) {
	if t.GetKvmInstanceNicsScript != "" {
		output, err := RunShellScript(t.GetKvmInstanceNicsScript, instanceName)
		if err != nil {
			return nil, err
		}
		return parseKvmInstanceNics(output)
	}

	return GetKvmInstanceNicsByVirsh(instanceName)
}
