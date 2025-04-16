package cpm

import (
	"reflect"
	"testing"

	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/agent"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/testutils"
)

type testTool struct {
	containerPids map[string]int
	kvmInstances  []string
	kvmInstNics   map[string][]string
}

func (t testTool) GetContainerHostPid(containerId string) (int, error) {
	v, ok := t.containerPids[containerId]
	if !ok {
		return 0, errors.Errorf("container %s not found", containerId)
	}
	return v, nil
}

func (t testTool) GetKvmInstances() ([]string, error) {
	return t.kvmInstances, nil
}

func (t testTool) GetKvmInstanceNics(instanceName string) ([]string, error) {
	v, ok := t.kvmInstNics[instanceName]
	if !ok {
		return nil, errors.Errorf("instance %s not found", instanceName)
	}
	return v, nil
}

func Test_tasksBuilder_1(t *testing.T) {
	var res SyncStrategyResponse
	require.NoError(t, testutils.LoadResultFromJSON("testdata/syncStrategy1.json", &res))

	tb := &tasksBuilder{
		tool:            testTool{},
		activeInstances: []string{},
		buffSize:        256,
	}
	for _, strategy := range res.Strategy {
		tb.addStrategy(strategy)
	}
	assert.Len(t, tb.warnings, 0)
	assert.Equal(t, []agent.TaskConfig{
		{
			Interface: "eth0",
			Snaplen:   lo.ToPtr(65535),
			Capturer: agent.CapturerConfig{
				Type: "libpcap",
				Libpcap: &agent.LibpcapConfig{
					BufferSizeMB: lo.ToPtr[uint64](256),
					TimeoutMs:    lo.ToPtr(0),
				},
			},
			Outputs: []agent.OutputConfig{
				{
					Type: "zmq",
					Zmq: &agent.ZmqOutputConfig{
						Host: "127.0.0.1",
						Port: 5555,
					},
				},
			},
		},
	}, tb.tasks)
}

func Test_tasksBuilder_2(t *testing.T) {
	var res SyncStrategyResponse
	require.NoError(t, testutils.LoadResultFromJSON("testdata/syncStrategy2.json", &res))

	tb := &tasksBuilder{
		tool:            testTool{},
		activeInstances: []string{},
		buffSize:        256,
	}
	for _, strategy := range res.Strategy {
		tb.addStrategy(strategy)
	}
	assert.Len(t, tb.warnings, 0)
	assert.Equal(t, []agent.TaskConfig{
		{
			Interface: "eth0",
			Snaplen:   lo.ToPtr(65535),
			ReqPattern: &agent.ReqPattern{
				Type: "custom",
				Custom: &agent.CustomReqPattern{
					Pattern: "host nic.eth0 and port 22",
				},
			},
			Capturer: agent.CapturerConfig{
				Type: "libpcap",
				Libpcap: &agent.LibpcapConfig{
					Bpf:          lo.ToPtr("host 10.1.1.1"),
					BufferSizeMB: lo.ToPtr[uint64](256),
					TimeoutMs:    lo.ToPtr(0),
				},
			},
			Outputs: []agent.OutputConfig{
				{
					Type:          "zmq",
					RateLimitMbps: lo.ToPtr[uint64](256),
					Zmq: &agent.ZmqOutputConfig{
						Host:       "127.0.0.1",
						Port:       5555,
						ServiceTag: lo.ToPtr[uint32](3456),
					},
				},
			},
		},
	}, tb.tasks)
}

func Test_parseStartup(t *testing.T) {
	type args struct {
		startup       string
		ignoreUnknown bool
	}
	tests := []struct {
		name    string
		args    args
		want    *startupArgs
		wantErr bool
	}{
		{
			args: args{
				startup: "",
			},
			want: &startupArgs{},
		},
		{
			args: args{
				startup: "-s 65535 -t 1000",
			},
			want: &startupArgs{
				Snaplen: lo.ToPtr(65535),
				Timeout: lo.ToPtr(1000),
			},
		},
		{
			args: args{
				startup: "--snaplen=65535 --timeout=1000",
			},
			want: &startupArgs{
				Snaplen: lo.ToPtr(65535),
				Timeout: lo.ToPtr(1000),
			},
		},
		{
			args: args{
				startup: "--snaplen 65535",
			},
			want: &startupArgs{
				Snaplen: lo.ToPtr(65535),
			},
		},
		{
			args: args{
				startup: "--snaplen 65535 --unknown=xxx",
			},
			wantErr: true,
		},
		{
			args: args{
				startup:       "--snaplen 65535 --unknown=xxx",
				ignoreUnknown: true,
			},
			want: &startupArgs{
				Snaplen: lo.ToPtr(65535),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseStartup(tt.args.startup, tt.args.ignoreUnknown)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseStartup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseStartup() = %v, want %v", got, tt.want)
			}
		})
	}
}
