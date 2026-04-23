package cpworker

import "time"

type InfoSummary struct {
	Version        string `mapstructure:"version"`
	Pid            int    `mapstructure:"pid"`
	UptimeSec      int64  `mapstructure:"uptime_sec"`
	ConfigPath     string `mapstructure:"config_path"`
	WorkingDir     string `mapstructure:"working_dir"`
	LogDestination string `mapstructure:"log_destination"`
	StartedAtSec   int64  `mapstructure:"started_at_sec"`
}

func (i InfoSummary) StartedAt() time.Time {
	return time.Unix(i.StartedAtSec, 0).UTC()
}

type PingResult struct {
	Seq  int           `json:"seq"`
	Rtt  time.Duration `json:"-"`
	When time.Time     `json:"-"`
}
