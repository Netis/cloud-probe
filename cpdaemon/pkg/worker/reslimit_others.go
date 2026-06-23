//go:build !linux

package worker

import (
	"github.com/pkg/errors"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/cgroup"
)

func CreateProcessResLimit(pid int, cfg ResLimitCfg, quota ResLimitQuota) (*cgroup.ProcessLimit, error) {
	return nil, errors.New("resource limit is not supported on this platform")
}
