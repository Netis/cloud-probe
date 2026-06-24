//go:build !linux

package cgroup

import "github.com/pkg/errors"

// verifySupported 标记当前平台是否支持写后校验（仅 linux 可读 /proc/<pid>/cgroup）。
const verifySupported = false

// DetectVersion 仅在 linux 上支持。
func DetectVersion(root string) (string, error) {
	return "", errors.New("cgroup auto-detect is only supported on linux")
}

// verifyProcessCgroup 在非 linux 上为空实现。调用方通过 verifySupported 跳过，不会真正执行。
func verifyProcessCgroup(pid int, version, expectedPath string) error {
	return errors.New("verify not supported on non-linux")
}
