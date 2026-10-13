package cpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
