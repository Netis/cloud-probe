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

// Validate 在启动时校验 cgroup 配置，让非法的 version 尽早 fail-loud，而不是拖到
// 第一次给 worker 加 CPU 限额时才在 CreateProcessLimit 里报错（甚至在不加限额时
// 永远不报）。合法取值：
//   - "auto"：自动探测（也是默认值，未配置时即此值）
//   - "v1" / "v2"：显式钉死
//
// 空字符串一律拒绝：默认值已是 "auto"，正常配置不会产生 ""，出现 "" 基本意味着
// env/模板渲染漏填，应当 fail-loud 抓出来，而不是悄悄当 auto 跑。
func (c CgroupCfg) Validate() error {
	switch c.Version {
	case "auto", VersionV1, VersionV2:
		return nil
	default:
		return errors.Errorf("invalid cgroup.version %q: expected one of auto, v1, v2", c.Version)
	}
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

// resolveVersion 解析最终使用的 cgroup 版本：显式 v1/v2 原样返回（不触发探测）；
// "auto" 走 DetectVersion，探测失败回退 v1（保持改动前的默认行为）。
// 纯 v2 节点会被正确识别，不会进入回退分支，不存在误降级风险。
// 空串等非法值已由 CgroupCfg.Validate 在启动时拒绝，正常不会走到这里。
func resolveVersion(cfg CgroupCfg) string {
	if cfg.Version != "auto" {
		return cfg.Version
	}
	detected, err := DetectVersion(cfg.Root)
	if err != nil {
		// 检测不出来（statfs 失败、legacy 单挂载 magic 等）时回退到 v1。
		slog.Default().Warn("detect cgroup version failed, fallback to v1",
			slog.String("root", cfg.Root), slog.Any("error", err))
		return VersionV1
	}
	slog.Default().Info("auto-detected cgroup version",
		slog.String("version", detected), slog.String("root", cfg.Root))
	return detected
}

func CreateProcessLimit(pid int, cfg CgroupCfg, limit CgroupLimit) (*ProcessLimit, error) {
	version := resolveVersion(cfg)

	cgroupName := fmt.Sprintf("pid-%d", pid)
	// 进程在对应控制器层级下的预期 cgroup 相对路径，用于写后校验。
	expectedPath := "/" + filepath.Join(cfg.Hierarchy, cgroupName)

	switch version {
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
		logVerifyProcessCgroup(pid, VersionV1, expectedPath)
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
		logVerifyProcessCgroup(pid, VersionV2, expectedPath)
		return pl, nil
	default:
		return nil, errors.Errorf("unknown cgroup version: %s", version)
	}
}

// logVerifyProcessCgroup 回读 /proc/<pid>/cgroup 校验进程是否真的进入目标 cgroup，
// 仅打印日志、不影响流程：校验失败往往意味着 cgroup 版本与节点实际模式不符，
// 此时 cpu 限制不会真正生效。
func logVerifyProcessCgroup(pid int, version, expectedPath string) {
	if !verifySupported {
		slog.Default().Info("verify process cgroup skipped",
			slog.Int("pid", pid), slog.String("version", version), slog.String("reason", "unsupported platform"))
		return
	}
	if err := verifyProcessCgroup(pid, version, expectedPath); err != nil {
		slog.Default().Warn("verify process cgroup failed, cpu limit may not take effect",
			slog.Int("pid", pid), slog.String("version", version), slog.Any("error", err))
		return
	}
	slog.Default().Info("verify process cgroup ok",
		slog.Int("pid", pid), slog.String("version", version), slog.String("expectedPath", expectedPath))
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
