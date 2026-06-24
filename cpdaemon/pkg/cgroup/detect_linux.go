//go:build linux

package cgroup

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// verifySupported 标记当前平台是否支持写后校验（仅 linux 可读 /proc/<pid>/cgroup）。
const verifySupported = true

// DetectVersion 根据 root 实际挂载的文件系统判断 cpu 控制器使用 v1 还是 v2。
//
// 注意：hybrid 模式下 root 是 tmpfs，cpu 控制器始终是 v1（v2 部分挂在
// /sys/fs/cgroup/unified 下且不含 cpu），因此只需区分根是否为 cgroup2fs。
func DetectVersion(root string) (string, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		return "", errors.Wrapf(err, "statfs %s failed", root)
	}
	switch int64(st.Type) {
	case unix.CGROUP2_SUPER_MAGIC: // cgroup2fs, unified v2
		return VersionV2, nil
	case unix.TMPFS_MAGIC, // tmpfs, v1/hybrid 的根（控制器挂载点的父目录）
		unix.CGROUP_SUPER_MAGIC: // cgroup v1 文件系统本身（root 直指某 v1 控制器挂载点）
		return VersionV1, nil
	default:
		return "", errors.Errorf("unexpected fs type 0x%x at %s, cannot detect cgroup version", st.Type, root)
	}
}

// verifyProcessCgroup 回读 /proc/<pid>/cgroup，确认进程的 cpu 控制器确实进入了
// expectedPath（期望的 cgroup 相对路径，如 "/cloud-probe/pid-18687"）。
// 返回 nil 表示校验通过；返回非 nil error 时，error 即为失败原因（供调用方打日志）。
//
// /proc/<pid>/cgroup 每行格式统一为三段：hierarchy-ID:controller-list:cgroup-path
//
//	v2 unified 行——hierarchy-ID 恒为 0、controller-list 为空：
//	    0::/cloud-probe/pid-18687
//	v1 行——hierarchy-ID 为非 0 编号、controller-list 为逗号分隔的控制器名：
//	    9:cpu,cpuacct:/cloud-probe/pid-18687
//	    （现场未生效时该行会是 9:cpu,cpuacct:/kubepods/burstable/pod.../...）
//
// 第三段（cgroup-path，即下方 actualPath）是进程相对于控制器挂载根的实际路径，
// 拿它与 expectedPath 比对即可判断进程是否真的进入了目标 cgroup。
func verifyProcessCgroup(pid int, version, expectedPath string) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return errors.Wrapf(err, "read /proc/%d/cgroup failed", pid)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		// 拆出三段：hierarchy-ID : controller-list : cgroup-path
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		hid, controllers, actualPath := parts[0], parts[1], parts[2]

		switch version {
		case VersionV2:
			// 定位 v2 unified 行：hierarchy-ID==0 且 controller-list 为空，例如
			//   0::/cloud-probe/pid-18687
			if hid == "0" && controllers == "" {
				// 用后缀匹配而非全等：/proc/<pid>/cgroup 的路径相对于控制器挂载根，
				// 当 cfg.Root 是子目录、或 daemon 处于容器 cgroup namespace 时，
				// actualPath 会带额外前缀。我们只需确认进程落在了预期的叶子下。
				if strings.HasSuffix(actualPath, expectedPath) {
					return nil
				}
				return errors.Errorf("process not in expected cgroup: want suffix %q, actual %q", expectedPath, actualPath)
			}
		case VersionV1:
			// 定位 v1 中挂着 cpu 控制器的行：controller-list 含 "cpu"，例如
			//   9:cpu,cpuacct:/cloud-probe/pid-18687
			for _, c := range strings.Split(controllers, ",") {
				if c != "cpu" {
					continue
				}
				// 同上，后缀匹配以容忍前缀差异（子目录 root / 容器 namespace）。
				if strings.HasSuffix(actualPath, expectedPath) {
					return nil
				}
				return errors.Errorf("process not in expected cpu cgroup: want suffix %q, actual %q (controllers=%s)", expectedPath, actualPath, controllers)
			}
		}
	}
	return errors.Errorf("no %s cpu cgroup line found for pid %d", version, pid)
}
