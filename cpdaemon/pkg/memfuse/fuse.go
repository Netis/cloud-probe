// Package memfuse decides when cpdaemon must stop, or refuse to start, cpworker because the host is short of
// memory. The fuse state is persisted by CPM; see docs/MEM-FUSE.md and docs/MEM-FUSE-CPM-CONTRACT.md.
package memfuse

import (
	"time"

	"github.com/pkg/errors"
)

type Config struct {
	CheckInterval time.Duration
	// FailThreshold is the number of consecutive runtime check hits that trips the fuse.
	FailThreshold int
	// MinAvailableMb is the reserve left to the host while the worker runs: the runtime threshold, and what the
	// startup check adds to the nic buffer. 0 means no reserve: memory may run out, and the runtime check never hits
	// since MemAvailable cannot drop below 0.
	MinAvailableMb uint64
}

func (c Config) Validate() error {
	if c.CheckInterval <= 0 {
		return errors.New("mem_fuse.check_interval must be > 0")
	}
	if c.FailThreshold < 1 {
		return errors.New("mem_fuse.fail_threshold must be >= 1")
	}
	return nil
}

type State int

const (
	Disabled State = iota
	Armed
	// Tripped means the worker was stopped but CPM has not acknowledged the report yet.
	Tripped
	// Fused means CPM persisted the fuse; only an administrator's clear releases it.
	Fused
)

func (s State) String() string {
	switch s {
	case Disabled:
		return "disabled"
	case Armed:
		return "armed"
	case Tripped:
		return "tripped"
	case Fused:
		return "fused"
	default:
		return "unknown"
	}
}

type Reason string

const (
	ReasonStartup Reason = "startup"
	ReasonRuntime Reason = "runtime"
)

// Reading is what the caller measured and derived from the current strategy.
type Reading struct {
	MemAvailableMb uint64
	WorkerRssMb    uint64
	// NicBufferCfgMb is the configured capture buffer of all tasks; the resident ring is up to twice that.
	NicBufferCfgMb uint64
	// NewNicBufferCfgMb is the configured buffer of the tasks about to open a ring; startup check only, 0 at runtime.
	NewNicBufferCfgMb uint64
	MemLimitMb        uint64
}

// NicBufferMb is the estimated upper bound of the resident kernel capture ring of a configured buffer: libpcap packs
// frames into page-aligned blocks, so the ring takes up to twice the configured size.
func NicBufferMb(cfgMb uint64) uint64 {
	return cfgMb * 2
}

func (r Reading) NicBufferMb() uint64 {
	return NicBufferMb(r.NicBufferCfgMb)
}

func (r Reading) NewNicBufferMb() uint64 {
	return NicBufferMb(r.NewNicBufferCfgMb)
}

// Snapshot records the reading of the moment the fuse tripped.
type Snapshot struct {
	Reason  Reason
	FusedAt time.Time
	Reading
}

// Fuse is the fuse state machine. It does no I/O and is not safe for concurrent use.
type Fuse struct {
	cfg     Config
	state   State
	enabled bool
	hits    int
	// snap is nil when not tripped/fused, and when the fused state was restored from CPM after a restart.
	snap *Snapshot
}

func New(cfg Config) *Fuse {
	return &Fuse{cfg: cfg}
}

func (f *Fuse) State() State {
	return f.state
}

func (f *Fuse) Snapshot() *Snapshot {
	return f.snap
}

// OnStrategy takes the switch and fuse state of a changed strategy (200) and reports whether the strategy may be
// applied. memFused=true wins over the switch. While tripped, CPM has not persisted the fuse yet, so its fields are
// ignored; once fused, memFused=false means an administrator cleared it.
func (f *Fuse) OnStrategy(enabled, fused bool) bool {
	f.enabled = enabled
	if f.state == Tripped {
		return false
	}
	if fused {
		f.state = Fused
		f.hits = 0
		return false
	}
	f.snap = nil
	f.hits = 0
	if enabled {
		f.state = Armed
	} else {
		f.state = Disabled
	}
	return true
}

// BeforeStart is the startup check and reports whether the ring about to be allocated may be: always while disabled,
// never while tripped or fused. While armed it passes when MemAvailable still covers that ring plus the runtime
// reserve; otherwise the fuse trips.
func (f *Fuse) BeforeStart(r Reading) bool {
	switch f.state {
	case Disabled:
		return true
	case Tripped, Fused:
		return false
	}
	if r.MemAvailableMb >= r.NewNicBufferMb()+f.cfg.MinAvailableMb {
		return true
	}
	f.trip(ReasonStartup, r)
	return false
}

// Check is the outcome of one runtime check.
type Check struct {
	// HitsBefore and Hits count consecutive hits before and after this check.
	HitsBefore int
	Hits       int
	Tripped    bool
}

// OnCheck is one runtime check. Only an armed fuse checks; otherwise there is no outcome.
func (f *Fuse) OnCheck(r Reading) Check {
	if f.state != Armed {
		return Check{}
	}
	c := Check{HitsBefore: f.hits}
	if r.MemAvailableMb >= f.cfg.MinAvailableMb {
		f.hits = 0
		return c
	}
	f.hits++
	c.Hits = f.hits
	if f.hits >= f.cfg.FailThreshold {
		f.trip(ReasonRuntime, r)
		c.Tripped = true
	}
	return c
}

func (f *Fuse) trip(reason Reason, r Reading) {
	f.state = Tripped
	f.snap = &Snapshot{Reason: reason, FusedAt: time.Now(), Reading: r}
}

// OnReportAck takes a 200 from the metrics report and returns true when it confirmed a tripped fuse.
func (f *Fuse) OnReportAck() bool {
	if f.state != Tripped {
		return false
	}
	f.state = Fused
	return true
}

// Reset forgets everything; the daemon id changed, so CPM keeps a separate record for the new one.
func (f *Fuse) Reset() {
	*f = Fuse{cfg: f.cfg}
}

// Report returns the state to report to CPM and, for a fuse round of this process, its snapshot. A fused state
// restored from CPM has no snapshot; it is reported as the normal state, which CPM never takes as a clear.
func (f *Fuse) Report() (State, *Snapshot) {
	if f.snap != nil {
		return Fused, f.snap
	}
	if f.state == Armed || (f.state == Fused && f.enabled) {
		return Armed, nil
	}
	return Disabled, nil
}
