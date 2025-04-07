//go:build !linux

package agent

import (
	"github.com/pkg/errors"
)

func CreateProcessResLimit(pid int, cfg ResLimitCfg, quota ResLimitQuota) (func() error, error) {
	return nil, errors.New("resource limit is not supported on this platform")
}
