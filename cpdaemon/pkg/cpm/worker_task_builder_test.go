package cpm

import (
	"reflect"
	"testing"

	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/testutils"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/worker"
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

func Test_workerTasksBuilder_1(t *testing.T) {
	var res SyncStrategyResponse
	require.NoError(t, testutils.LoadResultFromJSON("testdata/syncStrategy1.json", &res))

	tb := &workerTasksBuilder{
		tool:            testTool{},
		activeInstances: []string{},
		daemonUUID:      "796d506a-46a1-4f4e-bd9a-6075a49ac9f8",
		buffSize:        256,
	}
	for _, strategy := range res.Strategy {
		tb.addStrategy(strategy)
	}
	assert.Len(t, tb.warnings, 0)
	assert.Equal(t, []worker.TaskConfig{
		{
			Capturer: worker.CapturerConfig{
				Type: "libpcap",
				Libpcap: &worker.LibpcapConfig{
					Interface:    "eth0",
					Snaplen:      lo.ToPtr(65535),
					BufferSizeMB: lo.ToPtr[uint64](256),
					TimeoutMs:    lo.ToPtr(0),
				},
			},
			Outputs: []worker.OutputConfig{
				{
					Type: "zmq",
					Zmq: &worker.ZmqOutputConfig{
						Host: "127.0.0.1",
						Port: 5555,
						Hwm:  lo.ToPtr(2000),
						Uuid: "796d506a-46a1-4f4e-bd9a-6075a49ac9f8",
					},
				},
			},
		},
	}, tb.tasks)
}

func Test_workerTasksBuilder_2(t *testing.T) {
	var res SyncStrategyResponse
	require.NoError(t, testutils.LoadResultFromJSON("testdata/syncStrategy2.json", &res))

	tb := &workerTasksBuilder{
		tool:            testTool{},
		daemonUUID:      "796d506a-46a1-4f4e-bd9a-6075a49ac9f8",
		activeInstances: []string{},
		buffSize:        256,
	}
	for _, strategy := range res.Strategy {
		tb.addStrategy(strategy)
	}
	assert.Len(t, tb.warnings, 0)
	assert.Equal(t, []worker.TaskConfig{
		{
			ReqPattern: &worker.ReqPatternConfig{
				Type: "custom",
				Custom: &worker.CustomReqPatternConfig{
					Pattern: "host nic.eth0 and port 22",
				},
			},
			Capturer: worker.CapturerConfig{
				Type: "libpcap",
				Libpcap: &worker.LibpcapConfig{
					Interface:            "eth0",
					Snaplen:              lo.ToPtr(65535),
					Bpf:                  lo.ToPtr("host 10.1.1.1"),
					BufferSizeMB:         lo.ToPtr[uint64](256),
					TimeoutMs:            lo.ToPtr(0),
					NotFilterOutputHosts: lo.ToPtr(true),
				},
			},
			Outputs: []worker.OutputConfig{
				{
					Type:          "gre",
					RateLimitMbps: lo.ToPtr[uint64](256),
					Gre: &worker.GreOutputConfig{
						Host:       "2.2.2.2",
						ServiceTag: lo.ToPtr[uint32](3456),
						Pmtudisc:   lo.ToPtr("do"),
						BindDevice: lo.ToPtr("eth1"),
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
				startup: "-s 65535 -t 1000 -B eth1 -M do --zmq_hwm 1000 -p --cpu 2 --nofilter",
			},
			want: &startupArgs{
				Snaplen:     lo.ToPtr(65535),
				Timeout:     lo.ToPtr(1000),
				BindDevice:  lo.ToPtr("eth1"),
				Pmtudisc:    lo.ToPtr("do"),
				ZmqHwm:      lo.ToPtr(1000),
				Priority:    lo.ToPtr(true),
				CpuAffinity: lo.ToPtr(2),
				NoFilter:    lo.ToPtr(true),
			},
		},
		{
			args: args{
				startup: "--snaplen 65535 --timeout 1000 --bind_device eth1 --pmtudisc_option do --zmq_hwm 1000 --priority --cpu 2 --nofilter",
			},
			want: &startupArgs{
				Snaplen:     lo.ToPtr(65535),
				Timeout:     lo.ToPtr(1000),
				BindDevice:  lo.ToPtr("eth1"),
				Pmtudisc:    lo.ToPtr("do"),
				ZmqHwm:      lo.ToPtr(1000),
				Priority:    lo.ToPtr(true),
				CpuAffinity: lo.ToPtr(2),
				NoFilter:    lo.ToPtr(true),
			},
		},
		{
			args: args{
				startup: "--snaplen=65535 --timeout=1000 --bind_device=eth1 --pmtudisc_option=do --zmq_hwm=1000 --priority --cpu=2 --nofilter",
			},
			want: &startupArgs{
				Snaplen:     lo.ToPtr(65535),
				Timeout:     lo.ToPtr(1000),
				BindDevice:  lo.ToPtr("eth1"),
				Pmtudisc:    lo.ToPtr("do"),
				ZmqHwm:      lo.ToPtr(1000),
				Priority:    lo.ToPtr(true),
				CpuAffinity: lo.ToPtr(2),
				NoFilter:    lo.ToPtr(true),
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

func Test_Vni2Tag(t *testing.T) {
	tag := Vni2Tag{
		ObservationDomainId:    23,
		ExtensionFlag:          1,
		ObservationPointId:     6,
		ResourcePointDirection: 0,
	}
	assert.Equal(t, uint32(6040), tag.Encode())

	tag = Vni2Tag{
		ObservationDomainId:    3568,
		ExtensionFlag:          0,
		ObservationPointId:     9,
		ResourcePointDirection: 0,
	}
	assert.Equal(t, uint32(913444), tag.Encode())
}
