package cpm

import (
	"encoding/json"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Only a strategy that names KVM instances needs the active instance list.
func TestSyncStrategyResponse_HasInstances(t *testing.T) {
	assert.False(t, (&SyncStrategyResponse{}).HasInstances())
	assert.False(t, (&SyncStrategyResponse{Strategy: []StrategyEntry{
		{InterfaceNames: []string{"eth0"}, InstanceNames: []string{}},
	}}).HasInstances())
	assert.True(t, (&SyncStrategyResponse{Strategy: []StrategyEntry{
		{InterfaceNames: []string{"eth0"}},
		{InstanceNames: []string{"vm1"}},
	}}).HasInstances())
}

// An old CPM sends neither fuse field: the fuse is off and nothing is fused.
func TestSyncStrategyResponse_memFuseFields(t *testing.T) {
	var old SyncStrategyResponse
	require.NoError(t, json.Unmarshal([]byte(`{"version":3,"strategy":[]}`), &old))
	assert.False(t, old.MemFuseEnabled)
	assert.False(t, old.MemFused)

	var cur SyncStrategyResponse
	require.NoError(t, json.Unmarshal([]byte(`{"version":3,"memFuseEnabled":true,"memFused":true}`), &cur))
	assert.True(t, cur.MemFuseEnabled)
	assert.True(t, cur.MemFused)
}

func TestSyncStrategyResponse_EffectiveMemLimitMb(t *testing.T) {
	assert.Equal(t, uint64(512), (&SyncStrategyResponse{}).EffectiveMemLimitMb(512))
	assert.Equal(t, uint64(512), (&SyncStrategyResponse{MemLimit: lo.ToPtr(int64(0))}).EffectiveMemLimitMb(512))
	assert.Equal(t, uint64(2048), (&SyncStrategyResponse{MemLimit: lo.ToPtr(int64(2048))}).EffectiveMemLimitMb(512))
}

// Not fused: only state and the two thresholds. Fused: every field, a zero included, because CPM rejects a fused
// entry with a missing field.
func TestSyncMetricsRequest_memFuseJSON(t *testing.T) {
	keys := func(req SyncMetricsRequest) map[string]any {
		b, err := json.Marshal(req)
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(b, &m))
		return m
	}

	armed := keys(SyncMetricsRequest{MemFuse: &MemFuseEntry{State: "armed", NicBufferMb: 16, MinAvailableMb: 256}})
	assert.Equal(t, map[string]any{"state": "armed", "nicBufferMb": 16.0, "minAvailableMb": 256.0}, armed["memFuse"])

	fused := keys(SyncMetricsRequest{Logs: []LogEntry{}, MemFuse: &MemFuseEntry{
		State:          "fused",
		Reason:         lo.ToPtr("startup"),
		FusedTimestamp: lo.ToPtr(int64(1760580000)),
		NicBufferMb:    4096,
		MinAvailableMb: 256,
		MemLimitMb:     lo.ToPtr(uint64(2048)),
		MemAvailableMb: lo.ToPtr(uint64(335)),
		WorkerRssMb:    lo.ToPtr(uint64(0)),
	}})
	assert.Equal(t, map[string]any{
		"state":          "fused",
		"reason":         "startup",
		"fusedTimestamp": 1760580000.0,
		"nicBufferMb":    4096.0,
		"minAvailableMb": 256.0,
		"memLimitMb":     2048.0,
		"memAvailableMb": 335.0,
		"workerRssMb":    0.0,
	}, fused["memFuse"])
	assert.Contains(t, fused, "pid")
	assert.Nil(t, fused["pid"])
	assert.Contains(t, fused, "metrics")
	assert.Nil(t, fused["metrics"])
}
