package agent

import "github.com/Netis/cloud-probe/cpdaemon/pkg/cgroup"

type ResLimitCfg struct {
	CgroupCfg cgroup.CgroupCfg
}

type ResLimitQuota struct {
	CpuLimit *float64
}
