package cgroup

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestCgroupCfgValidate guards that startup validation accepts ""/auto/v1/v2 and
// rejects anything else (e.g. typos), so a bad version fails loudly at startup
// rather than at first cpu-limit application.
func TestCgroupCfgValidate(t *testing.T) {
	cases := []struct {
		version string
		wantErr bool
	}{
		{"auto", false},
		{"v1", false},
		{"v2", false},
		{"", true},
		{"V2", true},
		{"cgroupv2", true},
		{"2", true},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			err := CgroupCfg{Version: tc.version}.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate(version=%q) = nil, want error", tc.version)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate(version=%q) = %v, want nil", tc.version, err)
			}
		})
	}
}

// TestResolveVersion unit-tests version resolution in isolation, without any
// cgroup creation/quota/membership/verification side effects. Explicitly pinned
// "v1"/"v2" must be returned as-is without touching the root (proven by passing a
// nonexistent root that would error if DetectVersion were called); "auto" must
// resolve to a concrete version, falling back to v1 when the root is not cgroup2fs.
func TestResolveVersion(t *testing.T) {
	cases := []struct {
		name    string
		version string
		root    string
		want    string
	}{
		// explicit versions bypass detection: a bogus root must be ignored.
		{"explicit v1 skips detection", "v1", "/nonexistent-cgroup-root", "v1"},
		{"explicit v2 skips detection", "v2", "/nonexistent-cgroup-root", "v2"},
		// auto on a non-cgroup2fs root resolves to v1 (detected or fallback).
		{"auto resolves to v1", "auto", t.TempDir(), "v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveVersion(CgroupCfg{Version: tc.version, Root: tc.root})
			if got != tc.want {
				t.Fatalf("resolveVersion(version=%q, root=%q) = %q, want %q",
					tc.version, tc.root, got, tc.want)
			}
		})
	}
}

// TestCreateProcessLimit_Layout is the integration guard that the resolved cgroup
// version drives which on-disk layout is created end-to-end: explicit "v1"/"v2"
// reach their own branch, and "auto" resolves to a concrete version (falling back
// to v1 when the root's fs cannot be detected). Version resolution itself is
// covered by the lighter TestResolveVersion; this test exercises the full
// CreateProcessLimit path (dir creation + quota/procs writes). Using a temp dir as
// the cgroup root keeps the filesystem writes self-contained.
func TestCreateProcessLimit_Layout(t *testing.T) {
	const hierarchy = "cloud-probe-test"
	pid := os.Getpid()
	cgroupName := filepath.Join(hierarchy, "pid-"+strconv.Itoa(pid))

	cases := []struct {
		version  string
		wantPath string // path, relative to root, that must be created
	}{
		// explicit v1 → <root>/cpu/<hierarchy>/pid-N
		{"v1", filepath.Join("cpu", cgroupName)},
		// explicit v2 → <root>/<hierarchy>/pid-N
		{"v2", cgroupName},
		// auto → v1 layout (temp root is not cgroup2fs, so detection falls back to v1)
		{"auto", filepath.Join("cpu", cgroupName)},
	}

	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			root := t.TempDir()
			cfg := CgroupCfg{Version: tc.version, Root: root, Hierarchy: hierarchy}
			if _, err := CreateProcessLimit(pid, cfg, CgroupLimit{}); err != nil {
				t.Fatalf("CreateProcessLimit(%q) returned error: %v", tc.version, err)
			}
			if _, err := os.Stat(filepath.Join(root, tc.wantPath)); err != nil {
				t.Fatalf("expected cgroup dir %q under root for version %q: %v", tc.wantPath, tc.version, err)
			}
		})
	}
}

// TestSetV1CpuUnlimited verifies clearing a v1 limit writes -1 to
// cpu.cfs_quota_us without touching (removing) the cgroup directory. This is the
// regression guard for the reload-mode "device or resource busy" failure: the
// limit is cleared on a live worker by neutralizing the quota, not by rmdir.
func TestSetV1CpuUnlimited(t *testing.T) {
	dir := t.TempDir()
	quotaFile := filepath.Join(dir, "cpu.cfs_quota_us")
	// Pre-seed an existing limit, as if SetV1CpuQuota had run.
	if err := os.WriteFile(quotaFile, []byte("50000"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := SetV1CpuUnlimited(dir); err != nil {
		t.Fatalf("SetV1CpuUnlimited returned error: %v", err)
	}

	got, err := os.ReadFile(quotaFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "-1" {
		t.Fatalf("expected cpu.cfs_quota_us = -1, got %q", string(got))
	}
	// The cgroup directory must still exist (it is only removed on worker exit).
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("cgroup dir should still exist: %v", err)
	}
}

// TestSetV2CpuUnlimited verifies clearing a v2 limit writes "max" to cpu.max
// while leaving the cgroup directory in place.
func TestSetV2CpuUnlimited(t *testing.T) {
	dir := t.TempDir()
	maxFile := filepath.Join(dir, "cpu.max")
	if err := os.WriteFile(maxFile, []byte("50000 100000"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := SetV2CpuUnlimited(dir); err != nil {
		t.Fatalf("SetV2CpuUnlimited returned error: %v", err)
	}

	got, err := os.ReadFile(maxFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "max" {
		t.Fatalf("expected cpu.max = max, got %q", string(got))
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("cgroup dir should still exist: %v", err)
	}
}
