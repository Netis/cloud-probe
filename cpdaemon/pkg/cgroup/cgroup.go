package cgroup

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"

	"github.com/pkg/errors"
)

const (
	VersionV1 = "v1"
	VersionV2 = "v2"
)

type CgroupCfg struct {
	Version   string
	Root      string
	Hierarchy string
}

type CgroupLimit struct {
	CpuLimit *float64 // cpu usage percentage, eg: 100 means 100%
}

func CreateProcessLimit(pid int, cfg CgroupCfg, limit CgroupLimit) (func() error, error) {
	cgroupName := fmt.Sprintf("pid-%d", pid)
	switch cfg.Version {
	case VersionV1:
		cgroupPath, err := CreateV1CpuCgroup(cfg.Root, cfg.Hierarchy, cgroupName)
		if err != nil {
			return nil, err
		}
		slog.Default().Info("create cgroup", slog.String("cgroupPath", cgroupPath))

		clean := func() error {
			return RemoveCgroup(cgroupPath)
		}

		if limit.CpuLimit != nil {
			if err := SetV1CpuQuota(cgroupPath, *limit.CpuLimit); err != nil {
				return clean, err
			}
		}

		if err := AddCgroupProcess(cgroupPath, pid); err != nil {
			return clean, err
		}
		return clean, nil
	case VersionV2:
		cgroupPath, err := CreateV2Cgroup(cfg.Root, cfg.Hierarchy, cgroupName)
		if err != nil {
			return nil, err
		}
		slog.Default().Info("create cgroup", slog.String("cgroupPath", cgroupPath))

		clean := func() error {
			return RemoveCgroup(cgroupPath)
		}

		if limit.CpuLimit != nil {
			if err := SetV2CpuQuota(cgroupPath, *limit.CpuLimit); err != nil {
				return clean, err
			}
		}

		if err := AddCgroupProcess(cgroupPath, pid); err != nil {
			return clean, err
		}
		return clean, nil
	default:
		return nil, errors.Errorf("unknown cgroup version: %s", cfg.Version)
	}
}

func AddCgroupProcess(cgroupPath string, pid int) error {
	if err := os.WriteFile(
		filepath.Join(cgroupPath, "cgroup.procs"),
		[]byte(strconv.Itoa(pid)),
		0o644,
	); err != nil {
		return errors.Wrapf(err, "add cgroup process %d to %s failed", pid, cgroupPath)
	}
	return nil
}

func RemoveCgroup(cgroupPath string) error {
	if err := os.Remove(cgroupPath); err != nil {
		return errors.Wrapf(err, "remove cgroup %s failed", cgroupPath)
	}
	return nil
}

func CreateV1CpuCgroup(cgroupRoot string, cgroupHierarchy string, cgroupName string) (string, error) {
	// check cgroupRoot is exist
	if _, err := os.Stat(cgroupRoot); err != nil {
		return "", errors.Wrapf(err, "cgroupRoot %s not exist", cgroupRoot)
	}

	path := filepath.Join(cgroupRoot, "cpu", cgroupHierarchy, cgroupName)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", errors.Wrapf(err, "create cgroup %s failed", path)
	}
	return path, nil
}

func SetV1CpuQuota(cgroupPath string, cpuLimit float64) error {
	period := 100000
	quota := int(cpuLimit / 100 * float64(period))

	cpuQuotaFile := "cpu.cfs_quota_us"
	if err := os.WriteFile(
		filepath.Join(cgroupPath, cpuQuotaFile),
		[]byte(strconv.Itoa(quota)),
		0o644,
	); err != nil {
		return errors.Wrapf(err, "write %s for %s failed", cpuQuotaFile, cgroupPath)
	}

	cpuPeriodFile := "cpu.cfs_period_us"
	if err := os.WriteFile(
		filepath.Join(cgroupPath, cpuPeriodFile),
		[]byte(strconv.Itoa(period)),
		0o644,
	); err != nil {
		return errors.Wrapf(err, "write %s for %s failed", cpuPeriodFile, cgroupPath)
	}
	return nil
}

func CreateV2Cgroup(cgroupRoot string, cgroupHierarchy string, cgroupName string) (string, error) {
	// check cgroupRoot is exist
	if _, err := os.Stat(cgroupRoot); err != nil {
		return "", errors.Wrapf(err, "cgroupRoot %s not exist", cgroupRoot)
	}

	path := filepath.Join(cgroupRoot, cgroupHierarchy, cgroupName)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", errors.Wrapf(err, "create cgroup %s failed", path)
	}
	return path, nil
}

func SetV2CpuQuota(cgroupPath string, cpuLimit float64) error {
	period := 100000
	quota := int(cpuLimit / 100 * float64(period))

	cpuMaxFile := "cpu.max"
	if err := os.WriteFile(
		filepath.Join(cgroupPath, cpuMaxFile),
		[]byte(fmt.Sprintf("%d %d", quota, period)),
		0o644,
	); err != nil {
		return errors.Wrapf(err, "write %s for %s failed", cpuMaxFile, cgroupPath)
	}
	return nil
}
