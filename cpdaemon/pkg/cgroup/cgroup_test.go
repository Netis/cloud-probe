package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

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
