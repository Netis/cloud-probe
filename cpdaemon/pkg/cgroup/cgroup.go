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

// ProcessLimit is a handle to a process's cpu cgroup.
type ProcessLimit struct {
	// Reset clears the cpu quota (sets it to unlimited) while keeping the cgroup
	// and its process membership intact. It is safe to call while the worker is
	// still running, unlike Cleanup which would fail with EBUSY.
	Reset func() error
	// Cleanup removes the cgroup directory. It is intended for worker exit, when
	// the process has detached and the cgroup is empty.
	Cleanup func() error
}

func CreateProcessLimit(pid int, cfg CgroupCfg, limit CgroupLimit) (*ProcessLimit, error) {
	cgroupName := fmt.Sprintf("pid-%d", pid)
	switch cfg.Version {
	case VersionV1:
		cgroupPath, err := CreateV1CpuCgroup(cfg.Root, cfg.Hierarchy, cgroupName)
		if err != nil {
			return nil, err
		}
		slog.Default().Info("create cgroup", slog.String("cgroupPath", cgroupPath))

		pl := &ProcessLimit{
			Reset:   func() error { return SetV1CpuUnlimited(cgroupPath) },
			Cleanup: func() error { return RemoveCgroup(cgroupPath) },
		}

		if limit.CpuLimit != nil {
			if err := SetV1CpuQuota(cgroupPath, *limit.CpuLimit); err != nil {
				return pl, err
			}
		}

		if err := AddCgroupProcess(cgroupPath, pid); err != nil {
			return pl, err
		}
		return pl, nil
	case VersionV2:
		cgroupPath, err := CreateV2Cgroup(cfg.Root, cfg.Hierarchy, cgroupName, []string{"cpu"})
		if err != nil {
			return nil, err
		}
		slog.Default().Info("create cgroup", slog.String("cgroupPath", cgroupPath))

		pl := &ProcessLimit{
			Reset:   func() error { return SetV2CpuUnlimited(cgroupPath) },
			Cleanup: func() error { return RemoveCgroup(cgroupPath) },
		}

		if limit.CpuLimit != nil {
			if err := SetV2CpuQuota(cgroupPath, *limit.CpuLimit); err != nil {
				return pl, err
			}
		}

		if err := AddCgroupProcess(cgroupPath, pid); err != nil {
			return pl, err
		}
		return pl, nil
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

// RemoveCgroup removes the (empty) leaf cgroup directory. A cgroup can only be
// rmdir'd once it has no member processes, so this must not be called while the
// worker is still attached — it is intended for worker exit. To merely clear a
// live worker's limit, reset its quota to unlimited via SetV1CpuUnlimited /
// SetV2CpuUnlimited instead.
func RemoveCgroup(cgroupPath string) error {
	if err := os.Remove(cgroupPath); err != nil {
		return errors.Wrapf(err, "remove cgroup %s failed", cgroupPath)
	}
	return nil
}

func CreateV1CpuCgroup(cgroupRoot string, cgroupHierarchy string, cgroupName string) (string, error) {
	// check cgroupRoot is exist
	_, err := os.Stat(cgroupRoot)
	switch {
	case os.IsNotExist(err):
		return "", errors.Wrapf(err, "cgroupRoot %s not exist", cgroupRoot)
	case err != nil:
		return "", errors.Wrapf(err, "check cgroupRoot %s failed", cgroupRoot)
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

// SetV1CpuUnlimited removes the cpu bandwidth limit by writing -1 to
// cpu.cfs_quota_us, leaving the cgroup and its members in place.
func SetV1CpuUnlimited(cgroupPath string) error {
	cpuQuotaFile := "cpu.cfs_quota_us"
	if err := os.WriteFile(
		filepath.Join(cgroupPath, cpuQuotaFile),
		[]byte("-1"),
		0o644,
	); err != nil {
		return errors.Wrapf(err, "write %s for %s failed", cpuQuotaFile, cgroupPath)
	}
	return nil
}

func CreateV2Cgroup(cgroupRoot string, cgroupHierarchy string, cgroupName string, controls []string) (string, error) {
	// check cgroupRoot is exist
	_, err := os.Stat(cgroupRoot)
	switch {
	case os.IsNotExist(err):
		return "", errors.Wrapf(err, "cgroupRoot %s not exist", cgroupRoot)
	case err != nil:
		return "", errors.Wrapf(err, "check cgroupRoot %s failed", cgroupRoot)
	}

	if cgroupHierarchy != "" {
		hierarchyPath := filepath.Join(cgroupRoot, cgroupHierarchy)
		_, err := os.Stat(hierarchyPath)
		switch {
		case os.IsNotExist(err):
			if err := doCreateV2Cgroup(hierarchyPath, controls); err != nil {
				return "", err
			}
		case err != nil:
			return "", errors.Wrapf(err, "check cgroupRoot %s failed", cgroupRoot)
		}
	}

	path := filepath.Join(cgroupRoot, cgroupHierarchy, cgroupName)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", errors.Wrapf(err, "create cgroup %s failed", path)
	}
	return path, nil
}

func doCreateV2Cgroup(path string, controls []string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return errors.Wrapf(err, "create cgroup %s failed", path)
	}

	controlFile := filepath.Join(path, "cgroup.subtree_control")
	for _, control := range controls {
		if err := os.WriteFile(controlFile, []byte(fmt.Sprintf("+%s", control)), 0o644); err != nil {
			return errors.Wrapf(err, "write +%s for %s failed", control, controlFile)
		}
	}
	return nil
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

// SetV2CpuUnlimited removes the cpu bandwidth limit by writing "max" to cpu.max,
// leaving the cgroup and its members in place.
func SetV2CpuUnlimited(cgroupPath string) error {
	cpuMaxFile := "cpu.max"
	if err := os.WriteFile(
		filepath.Join(cgroupPath, cpuMaxFile),
		[]byte("max"),
		0o644,
	); err != nil {
		return errors.Wrapf(err, "write %s for %s failed", cpuMaxFile, cgroupPath)
	}
	return nil
}
