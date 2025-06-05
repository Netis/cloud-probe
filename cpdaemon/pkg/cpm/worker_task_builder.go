package cpm

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/samber/lo"
	flag "github.com/spf13/pflag"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/worker"
)

type workerTasksBuilder struct {
	tool            Tool
	daemonUUID      string
	activeInstances []string
	buffSize        uint64

	warnings []error
	tasks    []worker.TaskConfig
}

func (b *workerTasksBuilder) addStrategy(strategy StrategyEntry) {
	// check strategy is valid
	_, err := b.newTaskConfig(strategy, taskItem{nicName: "eth0", obsIdx: 0})
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}

	switch {
	case len(strategy.ContainerIds) > 0:
		b.addContainerIds(strategy)
	case len(strategy.InterfaceNames) > 0:
		for i, interfaceName := range strategy.InterfaceNames {
			b.addInterfaceName(strategy, interfaceName, i)
		}
	case len(strategy.InstanceNames) > 0:
		for i, instanceName := range strategy.InstanceNames {
			b.addInstanceName(strategy, instanceName, i)
		}
	}
}

func (b *workerTasksBuilder) addContainerIds(strategy StrategyEntry) {
	var idx int
	for _, containerId := range strategy.ContainerIds {
		// 来源旧版本C++实现，支持多个连续的下划线
		parts := strings.FieldsFunc(containerId, func(r rune) bool {
			return r == '_'
		})

		if len(parts) == 0 {
			b.warnings = append(b.warnings, errors.Errorf("invalid container id: %s", containerId))
			continue
		}

		nics := parts[1:]
		if len(nics) == 0 {
			// 未指定nic，默认使用eth0
			nics = []string{"eth0"}
		}

		hostPid, err := b.tool.GetContainerHostPid(containerId)
		if err != nil {
			b.warnings = append(b.warnings, errors.Wrapf(err, "get container(%s) host process id failed", containerId))
			idx += len(nics)
			continue
		}

		for _, nic := range nics {
			b.addContainerId(strategy, hostPid, nic, idx)
			idx++
		}
	}
}

func (b *workerTasksBuilder) addContainerId(strategy StrategyEntry, hostPid int, nic string, obsIdx int) {
	item := taskItem{
		nicName:     nic,
		netns:       fmt.Sprintf("/proc/%d/ns/net", hostPid),
		obsIdx:      obsIdx,
		dumpSubDirs: []string{strconv.Itoa(hostPid), nic},
	}

	task, err := b.newTaskConfig(strategy, item)
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}
	b.tasks = append(b.tasks, *task)
}

func (b *workerTasksBuilder) addInterfaceName(strategy StrategyEntry, interfaceName string, obsIdx int) {
	item := taskItem{
		nicName:     interfaceName,
		obsIdx:      obsIdx,
		dumpSubDirs: []string{interfaceName},
	}

	task, err := b.newTaskConfig(strategy, item)
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}
	b.tasks = append(b.tasks, *task)
}

func (b *workerTasksBuilder) addInstanceName(strategy StrategyEntry, instanceName string, obsIdx int) {
	if !slices.Contains(b.activeInstances, instanceName) {
		b.warnings = append(b.warnings, errors.Errorf("instance name not found: %s", instanceName))
		return
	}

	ifs, err := b.tool.GetKvmInstanceNics(instanceName)
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}
	if len(ifs) == 0 {
		b.warnings = append(b.warnings, errors.Errorf("instance %s has no interfaces", instanceName))
		return
	}

	item := taskItem{
		nicName:     ifs[0],
		obsIdx:      obsIdx,
		dumpSubDirs: []string{ifs[0]},
	}
	task, err := b.newTaskConfig(strategy, item)
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}

	b.tasks = append(b.tasks, *task)
}

func (b *workerTasksBuilder) newTaskConfig(strategy StrategyEntry, item taskItem) (*worker.TaskConfig, error) {
	task := worker.TaskConfig{
		Capturer: worker.CapturerConfig{
			Type: worker.CapturerType_Libpcap,
			Libpcap: &worker.LibpcapConfig{
				BufferSizeMB: lo.ToPtr(b.buffSize),
			},
		},
	}

	if strategy.Bpf != nil {
		task.Capturer.Libpcap.Bpf = strategy.Bpf
	}

	if strategy.Startup != nil {
		startupArgs, err := parseStartup(*strategy.Startup, true)
		if err != nil {
			return nil, errors.Wrapf(err, "parse startup failed: %s", *strategy.Startup)
		}
		if startupArgs.Snaplen != nil {
			task.Snaplen = lo.ToPtr(*startupArgs.Snaplen)
		}
		if startupArgs.Timeout != nil {
			task.Capturer.Libpcap.TimeoutMs = lo.ToPtr(int(*startupArgs.Timeout))
		}
	}

	if strategy.ReqPatternType != nil {
		switch *strategy.ReqPatternType {
		case ReqPatternType_AUTO:
			task.ReqPattern = &worker.ReqPatternConfig{
				Type: worker.ReqPatternType_AUTO,
			}
		case ReqPatternType_CUSTOM:
			task.ReqPattern = &worker.ReqPatternConfig{
				Type:   worker.ReqPatternType_CUSTOM,
				Custom: &worker.CustomReqPatternConfig{},
			}
			if strategy.ReqPattern != nil {
				task.ReqPattern.Custom.Pattern = *strategy.ReqPattern
			}
		}
	}

	output := worker.OutputConfig{}
	if strategy.SliceLen != nil && *strategy.SliceLen > 0 {
		output.Slice = lo.ToPtr(uint64(*strategy.SliceLen))
	}

	if strategy.ForwardRateLimit != nil && *strategy.ForwardRateLimit > 0 {
		output.RateLimitMbps = lo.ToPtr(uint64(*strategy.ForwardRateLimit))
	}

	switch strategy.PacketChannelType {
	case PacketChannelType_VXLAN:
		output.Type = worker.OutputType_Vxlan
		output.Vxlan = &worker.VxlanOutputConfig{
			Host: strategy.Address,
		}
		if strategy.Port != nil {
			output.Vxlan.Port = strategy.Port
		}

		if strategy.CapTime != nil {
			if *strategy.CapTime == 1 {
				output.Vxlan.CaptureTime = lo.ToPtr(true)
			} else {
				output.Vxlan.CaptureTime = lo.ToPtr(false)
			}
		}

		if strategy.ApiVersion == nil || *strategy.ApiVersion == "v1" {
			if strategy.HasServiceTag && strategy.ServiceTag != nil {
				output.Vxlan.Vni1 = lo.ToPtr(uint32(*strategy.ServiceTag))
			} else {
				output.Vxlan.Vni1 = lo.ToPtr(uint32(0xffffff))
			}
		} else {
			var tag Vni2Tag
			tag.ResourcePointDirection = 0
			if strategy.HasObservationTag {
				if len(strategy.ObservationDomainIds) > item.obsIdx {
					tag.ObservationDomainId = strategy.ObservationDomainIds[item.obsIdx]
				} else {
					tag.ObservationDomainId = 1
				}
				if len(strategy.ObservationPointIds) > item.obsIdx {
					tag.ObservationPointId = uint32(strategy.ObservationPointIds[item.obsIdx])
				} else {
					tag.ObservationPointId = 1
				}
			} else {
				tag.ObservationDomainId = 1
				tag.ObservationPointId = 1
			}
			if strategy.HasExtensionFlag && strategy.ExtensionFlag != nil {
				tag.ExtensionFlag = uint32(*strategy.ExtensionFlag)
			} else {
				tag.ExtensionFlag = 0
			}
			output.Vxlan.Vni2 = lo.ToPtr(tag.Encode())
		}

	case PacketChannelType_GRE:
		output.Type = worker.OutputType_Gre
		output.Gre = &worker.GreOutputConfig{
			Host: strategy.Address,
		}
		if strategy.HasServiceTag && strategy.ServiceTag != nil {
			output.Gre.ServiceTag = lo.ToPtr(uint32(*strategy.ServiceTag))
		}
	case PacketChannelType_ZMQ:
		output.Type = worker.OutputType_Zmq
		output.Zmq = &worker.ZmqOutputConfig{
			Host: strategy.Address,
			Uuid: b.daemonUUID,
		}
		if strategy.Port != nil {
			output.Zmq.Port = *strategy.Port
		} else {
			return nil, errors.New("missing zmq.port")
		}
		if strategy.HasServiceTag && strategy.ServiceTag != nil {
			output.Zmq.ServiceTag = lo.ToPtr(uint32(*strategy.ServiceTag))
		}
	case PacketChannelType_FILE:
		output.Type = worker.OutputType_RotatingFile
		if strategy.DumpDir == nil {
			return nil, errors.New("missing dumpDir")
		}

		dirParts := append([]string{*strategy.DumpDir}, item.dumpSubDirs...)
		fileRoot := filepath.Join(dirParts...)
		if err := os.MkdirAll(fileRoot, 0o755); err != nil {
			return nil, errors.Wrapf(err, "create dump dir failed: %s", fileRoot)
		}
		output.RotatingFile = &worker.RotatingFileOutputConfig{
			FileRoot: fileRoot,
		}
		if strategy.DumpInterval != nil {
			output.RotatingFile.MaxFileInterval = lo.ToPtr(int32(*strategy.DumpInterval))
		}
	default:
		return nil, errors.Errorf("packet channel type not supported: %s", strategy.PacketChannelType)
	}

	task.Outputs = append(task.Outputs, output)
	task.Interface = item.nicName
	if item.netns != "" {
		task.Netns = lo.ToPtr(item.netns)
	}
	return &task, nil
}

type taskItem struct {
	nicName string
	netns   string

	obsIdx      int
	dumpSubDirs []string
}

/*
typedef struct {
    uint32_t resourcePointDirection:2;
    uint32_t observationPointId:5;
    uint32_t extensionFlag:1;
    uint32_t observationDomainId:24;
} Vni2Tag;

int main() {
	uint32_t service_tag;
	Vni2Tag tag;
	tag.observationDomainId = 3568;
    tag.extensionFlag = 0;
    tag.observationPointId = 9;
    tag.resourcePointDirection = 0;
	memcpy(&serviceTag, &tag, sizeof(serviceTag));
}
*/

type Vni2Tag struct {
	ResourcePointDirection uint32 // 2bits
	ObservationPointId     uint32 // 5bits
	ExtensionFlag          uint32 // 1bit
	ObservationDomainId    uint32 // 24bits
}

func (t Vni2Tag) Encode() uint32 {
	return (t.ResourcePointDirection & 0x03) |
		(t.ObservationPointId&0x1F)<<2 |
		(t.ExtensionFlag&0x01)<<7 |
		(t.ObservationDomainId&0x00FFFFFF)<<8
}

type startupArgs struct {
	Snaplen *int
	Timeout *int
}

func parseStartup(startup string, ignoreUnknown bool) (*startupArgs, error) {
	args, err := splitArgs(startup)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	f := flag.NewFlagSet("", flag.ContinueOnError)
	snaplen := f.IntP("snaplen", "s", 0, "snaplen")
	timeout := f.IntP("timeout", "t", 0, "timeout")

	err = f.Parse(args)
	switch {
	case isUnknownFlagError(err):
		if !ignoreUnknown {
			return nil, errors.WithStack(err)
		}
	case err != nil:
		return nil, errors.WithStack(err)
	}

	res := &startupArgs{}
	if f.Changed("snaplen") {
		res.Snaplen = snaplen
	}
	if f.Changed("timeout") {
		res.Timeout = timeout
	}

	return res, nil
}
