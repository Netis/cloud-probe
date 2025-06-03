package cpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUuidGenConfig_Generate(t *testing.T) {
	t.Run("test01", func(t *testing.T) {
		t.Setenv("CPDAEMON_CPM_REG_NAME", "test01")
		cfg := UuidGenConfig{
			Type: "env",
			Env: UuidGenEnvConfig{
				Keys: []string{"CPDAEMON_CPM_REG_NAME"},
			},
		}
		v, err := cfg.Generate()
		require.NoError(t, err)
		assert.Equal(t, "65313836-6365-6463-3730-653235616237", v)
	})

	t.Run("test02", func(t *testing.T) {
		t.Setenv("CPDAEMON_CPM_REG_NAME", "test02")
		cfg := UuidGenConfig{
			Type: "env",
			Env: UuidGenEnvConfig{
				Keys: []string{"CPDAEMON_CPM_REG_NAME"},
			},
		}
		v, err := cfg.Generate()
		require.NoError(t, err)
		assert.Equal(t, "39653431-3366-3762-6262-366339653363", v)
	})
}
