package tool

import "github.com/pkg/errors"

type Tool struct {
	GetContainerHostPidScript string
	GetKvmInstancesScript     string
	GetKvmInstanceNicsScript  string
}

func (t Tool) GetContainerHostPid(containerId string) (int, error) {
	// 查看 k8s 容器运行时
	/*
		controlplane:~$ kubectl get nodes -o wide
		NAME           STATUS   ROLES           AGE   VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION     CONTAINER-RUNTIME
		controlplane   Ready    control-plane   41h   v1.33.2   172.30.1.2    <none>        Ubuntu 24.04.1 LTS   6.8.0-51-generic   containerd://1.7.27
		node01         Ready    <none>          41h   v1.33.2   172.30.2.2    <none>        Ubuntu 24.04.1 LTS   6.8.0-51-generic   containerd://1.7.27
	*/
	/*
		[root@k8s-master-2 ~]# kubectl get nodes -o wide
		NAME           STATUS   ROLES    AGE      VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE                KERNEL-VERSION                 CONTAINER-RUNTIME
		k8s-master-1   Ready    master   233d     v1.16.3   10.1.1.210    <none>        CentOS Linux 7 (Core)   3.10.0-693.el7.x86_64          docker://19.3.5
		worker-node1   Ready    <none>   224d     v1.16.3   10.1.1.48     <none>        CentOS Linux 7 (Core)   3.10.0-1160.el7.x86_64         docker://18.9.9
		worker-node2   Ready    <none>   224d     v1.16.3   10.1.1.50     <none>        CentOS Linux 7 (Core)   3.10.0-1160.el7.x86_64         docker://18.9.9
	*/
	if pid, err := GetContainerHostPidByDocker(containerId); err == nil {
		return pid, nil
	}

	if pid, err := GetContainerHostPidByCriPid(containerId); err == nil {
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
