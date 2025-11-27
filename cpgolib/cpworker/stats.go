package cpworker

import (
	"cmp"
)

const (
	EIB_IN_BYTES    = 1024 * 1024 * 1024 * 1024 * 1024 * 1024 // 1 EiB = 2^60 bytes
	PETA_IN_PACKETS = 10000000000000000                       // 1 Peta = 10^16 packets
)

type StatsSummary struct {
	Time struct {
		Sec  int64 `mapstructure:"sec"`
		Nsec int64 `mapstructure:"nsec"`
	} `mapstructure:"time"`
	Capture        CaptureStats        `mapstructure:"capture"`
	Output         OutputStats         `mapstructure:"output"`
	PipelineBuffer PipelineBufferStats `mapstructure:"pipeline_buffer"`
}

type PipelineBufferStats struct {
	MemTotal  uint64 `mapstructure:"mem_total"`
	MemUsed   uint64 `mapstructure:"mem_used"`
	RingTotal uint64 `mapstructure:"ring_total"`
	RingUsed  uint64 `mapstructure:"ring_used"`
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

	HeartbeatPackets PacketsStats `mapstructure:"heartbeat_packets"`
}

type BytesStats struct {
	Bytes uint64 `mapstructure:"bytes"`
	Eib   uint64 `mapstructure:"eib"`
}

func (s BytesStats) Compare(other BytesStats) int {
	return cmp.Or(
		cmp.Compare(s.Eib, other.Eib),
		cmp.Compare(s.Bytes, other.Bytes),
	)
}

func (s BytesStats) Sub(other BytesStats) (BytesStats, bool) {
	cmpRet := s.Compare(other)
	isLess := cmpRet < 0

	xStats := s
	yStats := other
	if isLess {
		xStats = other
		yStats = s
	}

	eib := xStats.Eib - yStats.Eib
	var bytes uint64
	if xStats.Bytes < yStats.Bytes {
		eib--
		bytes = EIB_IN_BYTES + xStats.Bytes - yStats.Bytes
	} else {
		bytes = xStats.Bytes - yStats.Bytes
	}

	return BytesStats{
		Bytes: bytes,
		Eib:   eib,
	}, isLess
}

type PacketsStats struct {
	Packets uint64 `mapstructure:"packets"`
	Peta    uint64 `mapstructure:"peta"`
}

func (s PacketsStats) Compare(other PacketsStats) int {
	return cmp.Or(
		cmp.Compare(s.Peta, other.Peta),
		cmp.Compare(s.Packets, other.Packets),
	)
}

func (s PacketsStats) Sub(other PacketsStats) (PacketsStats, bool) {
	cmpRet := s.Compare(other)
	isLess := cmpRet < 0

	xStats := s
	yStats := other
	if isLess {
		xStats = other
		yStats = s
	}

	peta := xStats.Peta - yStats.Peta
	var packets uint64
	if xStats.Packets < yStats.Packets {
		peta--
		packets = PETA_IN_PACKETS + xStats.Packets - yStats.Packets
	} else {
		packets = xStats.Packets - yStats.Packets
	}

	return PacketsStats{
		Packets: packets,
		Peta:    peta,
	}, isLess
}
