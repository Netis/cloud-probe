package memfuse

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCfg = Config{CheckInterval: 5 * time.Second, FailThreshold: 3, MinAvailableMb: 256}

// fuseIn builds a fuse in the given state the way the syncer would reach it.
func fuseIn(t *testing.T, state State) *Fuse {
	t.Helper()
	f := New(testCfg)
	switch state {
	case Disabled:
	case Armed:
		f.OnStrategy(true, false)
	case Tripped:
		f.OnStrategy(true, false)
		require.False(t, f.BeforeStart(Reading{MemAvailableMb: 0, NicBufferCfgMb: 8, NewNicBufferCfgMb: 8}))
	case Fused:
		f.OnStrategy(true, false)
		require.False(t, f.BeforeStart(Reading{MemAvailableMb: 0, NicBufferCfgMb: 8, NewNicBufferCfgMb: 8}))
		require.True(t, f.OnReportAck())
	}
	require.Equal(t, state, f.State())
	return f
}

// One row per strategy line of the transition table in MEM-FUSE.md 5.2.
func TestFuse_OnStrategy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		from      State
		enabled   bool
		fused     bool
		wantApply bool
		want      State
	}{
		{"disabled_enable", Disabled, true, false, true, Armed},
		{"armed_stay", Armed, true, false, true, Armed},
		{"disabled_stay", Disabled, false, false, true, Disabled},
		{"armed_disable", Armed, false, false, true, Disabled},
		{"disabled_fused_per_cpm", Disabled, false, true, false, Fused},
		{"armed_fused_per_cpm", Armed, true, true, false, Fused},
		{"tripped_ignores_clear", Tripped, true, false, false, Tripped},
		{"tripped_ignores_fused", Tripped, true, true, false, Tripped},
		{"tripped_ignores_disable", Tripped, false, false, false, Tripped},
		{"fused_stay", Fused, true, true, false, Fused},
		{"fused_switch_off_keeps_fuse", Fused, false, true, false, Fused},
		{"fused_cleared_armed", Fused, true, false, true, Armed},
		{"fused_cleared_disabled", Fused, false, false, true, Disabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fuseIn(t, tc.from)
			assert.Equal(t, tc.wantApply, f.OnStrategy(tc.enabled, tc.fused))
			assert.Equal(t, tc.want, f.State())
		})
	}
}

func TestFuse_clearDropsSnapshot(t *testing.T) {
	f := fuseIn(t, Fused)
	require.NotNil(t, f.Snapshot())
	f.OnStrategy(true, false)
	assert.Nil(t, f.Snapshot())
}

// The startup threshold is the upper bound of the ring about to open (configured × 2) plus the runtime reserve; the
// rings already resident are not counted again.
func TestFuse_BeforeStart(t *testing.T) {
	for _, tc := range []struct {
		name     string
		minAvail uint64
		newCfg   uint64
		avail    uint64
		wantPass bool
	}{
		{"equal_passes", 256, 100, 100*2 + 256, true},
		{"one_mb_less_trips", 256, 100, 100*2 + 256 - 1, false},
		{"no_reserve_equal_passes", 0, 100, 100 * 2, true},
		{"no_reserve_one_mb_less_trips", 0, 100, 100*2 - 1, false},
		{"only_the_new_ring_counts", 256, 10, 10*2 + 256, true},
		{"only_the_new_ring_counts_trips", 256, 10, 10*2 + 256 - 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testCfg
			cfg.MinAvailableMb = tc.minAvail
			f := New(cfg)
			f.OnStrategy(true, false)
			r := Reading{
				MemAvailableMb: tc.avail, NicBufferCfgMb: 100, NewNicBufferCfgMb: tc.newCfg, MemLimitMb: 2048, WorkerRssMb: 7,
			}
			assert.Equal(t, tc.wantPass, f.BeforeStart(r))
			if tc.wantPass {
				assert.Equal(t, Armed, f.State())
				assert.Nil(t, f.Snapshot())
				return
			}
			assert.Equal(t, Tripped, f.State())
			snap := f.Snapshot()
			require.NotNil(t, snap)
			assert.Equal(t, ReasonStartup, snap.Reason)
			assert.False(t, snap.FusedAt.IsZero())
			assert.Equal(t, r, snap.Reading)
			assert.Equal(t, uint64(200), snap.NicBufferMb())
		})
	}
}

// Only an armed fuse checks memory; a disabled one always lets the worker start, a tripped or fused one never does.
func TestFuse_BeforeStartWhenNotArmed(t *testing.T) {
	for _, tc := range []struct {
		state    State
		wantPass bool
	}{
		{Disabled, true},
		{Tripped, false},
		{Fused, false},
	} {
		t.Run(tc.state.String(), func(t *testing.T) {
			f := fuseIn(t, tc.state)
			snap := f.Snapshot()
			assert.Equal(t, tc.wantPass, f.BeforeStart(Reading{MemAvailableMb: 1 << 20}))
			assert.Equal(t, tc.state, f.State())
			assert.Same(t, snap, f.Snapshot(), "no new round")
		})
	}
}

func TestFuse_OnCheck(t *testing.T) {
	low := Reading{MemAvailableMb: 255, WorkerRssMb: 20, NicBufferCfgMb: 8, MemLimitMb: 512}
	ok := Reading{MemAvailableMb: 256}

	t.Run("trips_on_nth_consecutive_hit", func(t *testing.T) {
		f := fuseIn(t, Armed)
		assert.Equal(t, Check{HitsBefore: 0, Hits: 1}, f.OnCheck(low))
		assert.Equal(t, Check{HitsBefore: 1, Hits: 2}, f.OnCheck(low))
		assert.Equal(t, Check{HitsBefore: 2, Hits: 3, Tripped: true}, f.OnCheck(low))
		assert.Equal(t, Tripped, f.State())
		snap := f.Snapshot()
		require.NotNil(t, snap)
		assert.Equal(t, ReasonRuntime, snap.Reason)
		assert.Equal(t, low, snap.Reading)
	})
	t.Run("one_pass_resets", func(t *testing.T) {
		f := fuseIn(t, Armed)
		f.OnCheck(low)
		f.OnCheck(low)
		assert.Equal(t, Check{HitsBefore: 2, Hits: 0}, f.OnCheck(ok))
		f.OnCheck(low)
		assert.False(t, f.OnCheck(low).Tripped)
		assert.Equal(t, Armed, f.State())
	})
	// No reserve lets memory run out: MemAvailable is never below 0, so even an empty reading does not hit.
	t.Run("zero_reserve_never_hits", func(t *testing.T) {
		cfg := testCfg
		cfg.MinAvailableMb = 0
		f := New(cfg)
		f.OnStrategy(true, false)
		for range 5 {
			assert.Equal(t, Check{}, f.OnCheck(Reading{}))
		}
		assert.Equal(t, Armed, f.State())
	})
	t.Run("only_when_armed", func(t *testing.T) {
		for _, state := range []State{Disabled, Tripped, Fused} {
			f := fuseIn(t, state)
			for range 5 {
				assert.Equal(t, Check{}, f.OnCheck(low), state.String())
			}
			assert.Equal(t, state, f.State())
		}
	})
	// A runtime trip leaves hits at the threshold; a check while tripped must not report them as a new failure.
	t.Run("no_outcome_after_trip", func(t *testing.T) {
		f := fuseIn(t, Armed)
		for range testCfg.FailThreshold {
			f.OnCheck(low)
		}
		require.Equal(t, Tripped, f.State())
		assert.Equal(t, Check{}, f.OnCheck(low))
	})
	t.Run("disable_resets_hits", func(t *testing.T) {
		f := fuseIn(t, Armed)
		f.OnCheck(low)
		f.OnCheck(low)
		f.OnStrategy(false, false)
		f.OnStrategy(true, false)
		assert.Equal(t, 1, f.OnCheck(low).Hits)
	})
}

func TestFuse_OnReportAck(t *testing.T) {
	f := fuseIn(t, Tripped)
	assert.True(t, f.OnReportAck())
	assert.Equal(t, Fused, f.State())
	assert.False(t, f.OnReportAck(), "already fused")

	for _, state := range []State{Disabled, Armed} {
		f := fuseIn(t, state)
		assert.False(t, f.OnReportAck())
		assert.Equal(t, state, f.State())
	}
}

func TestFuse_Reset(t *testing.T) {
	f := fuseIn(t, Fused)
	f.Reset()
	assert.Equal(t, Disabled, f.State())
	assert.Nil(t, f.Snapshot())
	state, snap := f.Report()
	assert.Equal(t, Disabled, state)
	assert.Nil(t, snap)
}

func TestFuse_Report(t *testing.T) {
	t.Run("tripped_reported_as_fused", func(t *testing.T) {
		state, snap := fuseIn(t, Tripped).Report()
		assert.Equal(t, Fused, state)
		assert.NotNil(t, snap)
	})
	t.Run("fused_keeps_round", func(t *testing.T) {
		f := fuseIn(t, Fused)
		before := *f.Snapshot()
		f.OnStrategy(true, true)
		state, snap := f.Report()
		assert.Equal(t, Fused, state)
		assert.Equal(t, before, *snap)
	})
	// After a restart CPM says fused but this process has no round to report; CPM never clears on a normal state.
	t.Run("restored_fused_reported_as_normal", func(t *testing.T) {
		f := New(testCfg)
		f.OnStrategy(true, true)
		state, snap := f.Report()
		assert.Equal(t, Armed, state)
		assert.Nil(t, snap)

		f = New(testCfg)
		f.OnStrategy(false, true)
		state, _ = f.Report()
		assert.Equal(t, Disabled, state)
	})
	t.Run("armed_and_disabled", func(t *testing.T) {
		state, snap := fuseIn(t, Armed).Report()
		assert.Equal(t, Armed, state)
		assert.Nil(t, snap)
		state, _ = fuseIn(t, Disabled).Report()
		assert.Equal(t, Disabled, state)
	})
}

func TestConfig_Validate(t *testing.T) {
	assert.NoError(t, testCfg.Validate())
	zeroMin := testCfg
	zeroMin.MinAvailableMb = 0
	assert.NoError(t, zeroMin.Validate())

	noInterval := testCfg
	noInterval.CheckInterval = 0
	assert.ErrorContains(t, noInterval.Validate(), "check_interval")
	noThreshold := testCfg
	noThreshold.FailThreshold = 0
	assert.ErrorContains(t, noThreshold.Validate(), "fail_threshold")
}
