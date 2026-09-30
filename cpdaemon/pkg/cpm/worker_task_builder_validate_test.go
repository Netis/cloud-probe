package cpm

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Strategy values that cpworker would reject must drop only their own strategy, with a
// warning, instead of reaching the worker config and failing every reload (#259).

func validStrategy(t *testing.T, channel string) StrategyEntry {
	s := StrategyEntry{
		InterfaceNames:    []string{"eth0"},
		PacketChannelType: channel,
		Address:           "10.0.0.1",
	}
	switch channel {
	case PacketChannelType_ZMQ:
		s.Port = lo.ToPtr[int32](5555)
	case PacketChannelType_FILE:
		s.DumpDir = lo.ToPtr(t.TempDir())
	}
	return s
}

func buildOne(t *testing.T, s StrategyEntry) (int, []error) {
	tb := &workerTaskBuilder{tool: testTool{}, buffSize: 256}
	tb.addStrategy(s)
	tasks, warnings := tb.build()
	return len(tasks), warnings
}

func Test_workerTaskBuilder_rejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name    string
		channel string
		mutate  func(s *StrategyEntry)
		errPart string
	}{
		{"zmq_port_missing", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.Port = nil }, "zmq.port"},
		{"zmq_port_0", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.Port = lo.ToPtr[int32](0) }, "port"},
		{"zmq_port_70000", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.Port = lo.ToPtr[int32](70000) }, "port"},
		{"zmq_port_negative", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.Port = lo.ToPtr[int32](-1) }, "port"},
		{"vxlan_port_70000", PacketChannelType_VXLAN, func(s *StrategyEntry) { s.Port = lo.ToPtr[int32](70000) }, "port"},
		{"zmq_heartbeat_60001", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.ZmqHeartbeatMs = lo.ToPtr[int32](60001) }, "zmqHeartbeatMs"},
		{"zmq_heartbeat_negative", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.ZmqHeartbeatMs = lo.ToPtr[int32](-1) }, "zmqHeartbeatMs"},
		{"zmq_service_tag_negative", PacketChannelType_ZMQ, func(s *StrategyEntry) {
			s.HasServiceTag = true
			s.ServiceTag = lo.ToPtr[int32](-1)
		}, "serviceTag"},
		{"gre_service_tag_negative", PacketChannelType_GRE, func(s *StrategyEntry) {
			s.HasServiceTag = true
			s.ServiceTag = lo.ToPtr[int32](-1)
		}, "serviceTag"},
		{"vxlan_service_tag_negative", PacketChannelType_VXLAN, func(s *StrategyEntry) {
			s.HasServiceTag = true
			s.ServiceTag = lo.ToPtr[int32](-1)
		}, "serviceTag"},
		{"vxlan_split_bytes_70000", PacketChannelType_VXLAN, func(s *StrategyEntry) {
			s.HasPacketSplit = true
			s.PacketSplitBytes = lo.ToPtr[int32](70000)
		}, "packetSplitBytes"},
		{"vxlan_split_bytes_negative", PacketChannelType_VXLAN, func(s *StrategyEntry) {
			s.HasPacketSplit = true
			s.PacketSplitBytes = lo.ToPtr[int32](-1)
		}, "packetSplitBytes"},
		{"file_dump_interval_negative", PacketChannelType_FILE, func(s *StrategyEntry) { s.DumpInterval = lo.ToPtr[int32](-1) }, "dumpInterval"},
		{"startup_pmtudisc_bogus", PacketChannelType_GRE, func(s *StrategyEntry) { s.Startup = lo.ToPtr("--pmtudisc_option sometimes") }, "pmtudisc"},
		{"startup_timeout_negative", PacketChannelType_GRE, func(s *StrategyEntry) { s.Startup = lo.ToPtr("-t -1") }, "timeout"},
		{"startup_zmq_hwm_negative", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.Startup = lo.ToPtr("--zmq_hwm -1") }, "zmq_hwm"},
		{"req_pattern_custom_missing", PacketChannelType_GRE, func(s *StrategyEntry) {
			s.ReqPatternType = lo.ToPtr(ReqPatternType_CUSTOM)
		}, "reqPattern"},
		{"req_pattern_custom_empty", PacketChannelType_GRE, func(s *StrategyEntry) {
			s.ReqPatternType = lo.ToPtr(ReqPatternType_CUSTOM)
			s.ReqPattern = lo.ToPtr("  ")
		}, "reqPattern"},
		{"gre_address_empty", PacketChannelType_GRE, func(s *StrategyEntry) { s.Address = "" }, "address"},
		{"gre_address_hostname", PacketChannelType_GRE, func(s *StrategyEntry) { s.Address = "collector.example" }, "address"},
		{"vxlan_address_ipv6", PacketChannelType_VXLAN, func(s *StrategyEntry) { s.Address = "2001:db8::1" }, "address"},
		{"vxlan_address_v4_mapped", PacketChannelType_VXLAN, func(s *StrategyEntry) { s.Address = "::ffff:10.0.0.1" }, "address"},
		{"zmq_address_empty", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.Address = "" }, "address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validStrategy(t, tc.channel)
			tc.mutate(&s)
			n, warnings := buildOne(t, s)
			assert.Equal(t, 0, n, "invalid strategy must not produce a task")
			require.Len(t, warnings, 1)
			assert.Contains(t, warnings[0].Error(), tc.errPart)
		})
	}
}

func Test_workerTaskBuilder_acceptsBoundaryValues(t *testing.T) {
	cases := []struct {
		name    string
		channel string
		mutate  func(s *StrategyEntry)
	}{
		{"zmq_port_1", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.Port = lo.ToPtr[int32](1) }},
		{"zmq_port_65535", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.Port = lo.ToPtr[int32](65535) }},
		{"zmq_heartbeat_0", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.ZmqHeartbeatMs = lo.ToPtr[int32](0) }},
		{"zmq_heartbeat_60000", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.ZmqHeartbeatMs = lo.ToPtr[int32](60000) }},
		// libzmq resolves host names, so only an empty zmq address is invalid.
		{"zmq_address_hostname", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.Address = "collector.example" }},
		{"zmq_service_tag_0", PacketChannelType_ZMQ, func(s *StrategyEntry) {
			s.HasServiceTag = true
			s.ServiceTag = lo.ToPtr[int32](0)
		}},
		// A service tag that is not used (HasServiceTag false) is not checked.
		{"gre_unused_service_tag", PacketChannelType_GRE, func(s *StrategyEntry) { s.ServiceTag = lo.ToPtr[int32](-1) }},
		{"vxlan_split_bytes_65535", PacketChannelType_VXLAN, func(s *StrategyEntry) {
			s.HasPacketSplit = true
			s.PacketSplitBytes = lo.ToPtr[int32](65535)
		}},
		{"file_dump_interval_0", PacketChannelType_FILE, func(s *StrategyEntry) { s.DumpInterval = lo.ToPtr[int32](0) }},
		{"startup_pmtudisc_dont", PacketChannelType_VXLAN, func(s *StrategyEntry) { s.Startup = lo.ToPtr("-M dont -t 0") }},
		// zmq_hwm and pmtudisc only reach outputs that use them.
		{"gre_ignores_zmq_hwm", PacketChannelType_GRE, func(s *StrategyEntry) { s.Startup = lo.ToPtr("--zmq_hwm -1") }},
		{"zmq_ignores_pmtudisc", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.Startup = lo.ToPtr("-M sometimes") }},
		{"startup_zmq_hwm_0", PacketChannelType_ZMQ, func(s *StrategyEntry) { s.Startup = lo.ToPtr("--zmq_hwm 0") }},
		// cpworker clamps snaplen instead of rejecting it.
		{"startup_snaplen_huge", PacketChannelType_GRE, func(s *StrategyEntry) { s.Startup = lo.ToPtr("-s 1000000") }},
		{"req_pattern_custom", PacketChannelType_GRE, func(s *StrategyEntry) {
			s.ReqPatternType = lo.ToPtr(ReqPatternType_CUSTOM)
			s.ReqPattern = lo.ToPtr("port 80")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validStrategy(t, tc.channel)
			tc.mutate(&s)
			n, warnings := buildOne(t, s)
			assert.Empty(t, warnings)
			assert.Equal(t, 1, n)
		})
	}
}

// One bad strategy must not take the valid ones down with it.
func Test_workerTaskBuilder_invalidStrategyDoesNotAffectOthers(t *testing.T) {
	bad := validStrategy(t, PacketChannelType_ZMQ)
	bad.Port = lo.ToPtr[int32](70000)
	good := validStrategy(t, PacketChannelType_GRE)
	good.InterfaceNames = []string{"eth1"}

	tb := &workerTaskBuilder{tool: testTool{}, buffSize: 256}
	tb.addStrategy(bad)
	tb.addStrategy(good)
	tasks, warnings := tb.build()

	require.Len(t, warnings, 1)
	require.Len(t, tasks, 1)
	assert.Equal(t, "eth1", tasks[0].Capturer.Libpcap.Interface)
}
