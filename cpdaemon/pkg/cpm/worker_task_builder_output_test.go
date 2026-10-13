package cpm

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/worker"
)

// buildOutput runs one valid strategy through the builder and returns the output of its task.
func buildOutput(t *testing.T, s StrategyEntry) worker.OutputConfig {
	t.Helper()
	tb := &workerTaskBuilder{tool: testTool{}, buffSize: 256}
	tb.addStrategy(s)
	tasks, warnings := tb.build()
	require.Empty(t, warnings)
	require.Len(t, tasks, 1)
	require.Len(t, tasks[0].Outputs, 1)
	return tasks[0].Outputs[0]
}

// The strategy fields that reach the cpworker output config (docs/USAGE-CPWORKER.md).
func Test_workerTaskBuilder_outputFields(t *testing.T) {
	t.Run("forward_rate_limit", func(t *testing.T) {
		s := validStrategy(t, PacketChannelType_GRE)
		s.ForwardRateLimit = lo.ToPtr[int32](10)
		assert.Equal(t, lo.ToPtr[uint64](10), buildOutput(t, s).RateLimitMbps)

		// 0 means no limit: cpworker's rate_limit_mbps is left unset.
		s.ForwardRateLimit = lo.ToPtr[int32](0)
		assert.Nil(t, buildOutput(t, s).RateLimitMbps)
	})

	t.Run("vxlan_port", func(t *testing.T) {
		s := validStrategy(t, PacketChannelType_VXLAN)
		s.Port = lo.ToPtr[int32](4790)
		assert.Equal(t, lo.ToPtr[int32](4790), buildOutput(t, s).Vxlan.Port)
	})

	t.Run("zmq_service_tag", func(t *testing.T) {
		s := validStrategy(t, PacketChannelType_ZMQ)
		s.HasServiceTag = true
		s.ServiceTag = lo.ToPtr[int32](7)
		assert.Equal(t, lo.ToPtr[uint32](7), buildOutput(t, s).Zmq.ServiceTag)
	})

	t.Run("file_dump_interval", func(t *testing.T) {
		s := validStrategy(t, PacketChannelType_FILE)
		s.DumpInterval = lo.ToPtr[int32](60)
		assert.Equal(t, lo.ToPtr[int32](60), buildOutput(t, s).RotatingFile.MaxFileInterval)
	})
}

// The VXLAN tag format follows apiVersion (docs/VXLAN-WIRE-FORMAT.md §8): unset or "v1" sends
// vni1, the service tag or 0xFFFFFF without one; any other version sends vni2.
func Test_workerTaskBuilder_vxlanTagFormat(t *testing.T) {
	// vni2 with no observation tag: domain 1 (bits 8-31) and point 1 (bits 2-6), §5.
	const defaultVni2 = 1<<8 | 1<<2

	cases := []struct {
		name       string
		apiVersion *string
		serviceTag *int32
		vni1       *uint32
		vni2       *uint32
	}{
		{"unset_with_tag", nil, lo.ToPtr[int32](0x1A2), lo.ToPtr[uint32](0x1A2), nil},
		{"unset_without_tag", nil, nil, lo.ToPtr[uint32](0xFFFFFF), nil},
		{"v1_with_tag", lo.ToPtr("v1"), lo.ToPtr[int32](0x1A2), lo.ToPtr[uint32](0x1A2), nil},
		{"v2", lo.ToPtr("v2"), lo.ToPtr[int32](0x1A2), nil, lo.ToPtr[uint32](defaultVni2)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validStrategy(t, PacketChannelType_VXLAN)
			s.ApiVersion = tc.apiVersion
			s.HasServiceTag = tc.serviceTag != nil
			s.ServiceTag = tc.serviceTag
			out := buildOutput(t, s)
			assert.Equal(t, tc.vni1, out.Vxlan.Vni1)
			assert.Equal(t, tc.vni2, out.Vxlan.Vni2)
		})
	}
}

// vni2 carries the observation domain and point of the interface and the extension flag.
// Domain 3568 and point 9 are the vni2 example of docs/VXLAN-WIRE-FORMAT.md §9 (0xDF024);
// the extension flag sets bit 7 (§5).
func Test_workerTaskBuilder_vni2Tag(t *testing.T) {
	s := validStrategy(t, PacketChannelType_VXLAN)
	s.ApiVersion = lo.ToPtr("v2")
	s.HasObservationTag = true
	s.ObservationDomainIds = []uint32{3568}
	s.ObservationPointIds = []uint8{9}
	assert.Equal(t, lo.ToPtr[uint32](0xDF024), buildOutput(t, s).Vxlan.Vni2)

	s.HasExtensionFlag = true
	s.ExtensionFlag = lo.ToPtr[int8](1)
	assert.Equal(t, lo.ToPtr[uint32](0xDF0A4), buildOutput(t, s).Vxlan.Vni2)

	// An interface without an id of its own gets domain 1 and point 1.
	s.HasExtensionFlag = false
	s.ObservationDomainIds = nil
	s.ObservationPointIds = nil
	assert.Equal(t, lo.ToPtr[uint32](1<<8|1<<2), buildOutput(t, s).Vxlan.Vni2)
}
