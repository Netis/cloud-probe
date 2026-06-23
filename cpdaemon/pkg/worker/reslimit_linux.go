//go:build linux

package worker

import "github.com/Netis/cloud-probe/cpdaemon/pkg/cgroup"

func CreateProcessResLimit(pid int, cfg ResLimitCfg, quota ResLimitQuota) (*cgroup.ProcessLimit, error) {
	return cgroup.CreateProcessLimit(pid, cfg.CgroupCfg, cgroup.CgroupLimit{CpuLimit: quota.CpuLimit})
}
