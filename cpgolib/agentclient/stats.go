package agentclient

type Stats struct {
	Time struct {
		Sec  int64 `mapstructure:"sec"`
		Nsec int64 `mapstructure:"nsec"`
	} `mapstructure:"time"`
	Tasks []TaskStats `mapstructure:"tasks"`
}

type TaskStats struct {
	Index   int           `mapstructure:"index"`
	Capture CaptureStats  `mapstructure:"capture"`
	Outputs []OutputStats `mapstructure:"outputs"`
}

type CaptureStats struct {
	CapBytes   BytesStats   `mapstructure:"cap_bytes"`
	CapPackets PacketsStats `mapstructure:"cap_packets"`

	DropPackets   PacketsStats `mapstructure:"drop_packets"`
	IfdropPackets PacketsStats `mapstructure:"ifdrop_packets"`
}

type OutputStats struct {
	FwdBytes   BytesStats   `mapstructure:"fwd_bytes"`
	FwdPackets PacketsStats `mapstructure:"fwd_packets"`

	DirectionDropBytes   BytesStats   `mapstructure:"direction_drop_bytes"`
	DirectionDropPackets PacketsStats `mapstructure:"direction_drop_packets"`

	ErrorDropBytes   BytesStats   `mapstructure:"error_drop_bytes"`
	ErrorDropPackets PacketsStats `mapstructure:"error_drop_packets"`

	RatelimitDropBytes   BytesStats   `mapstructure:"ratelimit_drop_bytes"`
	RatelimitDropPackets PacketsStats `mapstructure:"ratelimit_drop_packets"`
}

type BytesStats struct {
	Bytes uint64 `mapstructure:"bytes"`
	Eib   uint64 `mapstructure:"eib"`
}

type PacketsStats struct {
	Packets uint64 `mapstructure:"packets"`
	Peta    uint64 `mapstructure:"peta"`
}
