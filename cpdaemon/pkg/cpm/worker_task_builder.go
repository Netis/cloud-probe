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

	"github.com/Netis/cloud-probe/cpdaemon/pkg/common"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/worker"
)

type workerTaskBuilder struct {
	tool            Tool
	daemonUUID      string
	activeInstances []string
	buffSize        uint64

	warnings []error
	tasks    []*worker.TaskConfig
}

func (b *workerTaskBuilder) addStrategy(strategy StrategyEntry) {
	// check strategy is valid
	_, err := b.newTaskConfig(strategy, taskItem{
		nicName: "eth0",
		obsIdx:  0,
		typ:     TaskTypeInterface,
	})
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

func (b *workerTaskBuilder) addContainerIds(strategy StrategyEntry) {
	var idx int
	for _, cId := range strategy.ContainerIds {
		containerId, nics := decodeContainerId(cId)
		if containerId == "" {
			b.warnings = append(b.warnings, errors.Errorf("invalid container id: %s", cId))
			continue
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

func (b *workerTaskBuilder) addContainerId(strategy StrategyEntry, hostPid int, nic string, obsIdx int) {
	item := taskItem{
		typ:         TaskTypeContainer,
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
	b.tasks = append(b.tasks, task)
}

func (b *workerTaskBuilder) addInterfaceName(strategy StrategyEntry, interfaceName string, obsIdx int) {
	item := taskItem{
		typ:         TaskTypeInterface,
		nicName:     interfaceName,
		obsIdx:      obsIdx,
		dumpSubDirs: []string{interfaceName},
	}

	task, err := b.newTaskConfig(strategy, item)
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}

	b.tasks = append(b.tasks, task)
}

func (b *workerTaskBuilder) addInstanceName(strategy StrategyEntry, instanceName string, obsIdx int) {
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
		typ:         TaskTypeKvmInstance,
		nicName:     ifs[0],
		obsIdx:      obsIdx,
		dumpSubDirs: []string{ifs[0]},
	}
	task, err := b.newTaskConfig(strategy, item)
	if err != nil {
		b.warnings = append(b.warnings, err)
		return
	}

	b.tasks = append(b.tasks, task)
}

func (b *workerTaskBuilder) newTaskConfig(strategy StrategyEntry, item taskItem) (*worker.TaskConfig, error) {
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

	startupArgs := &startupArgs{}
	if strategy.Startup != nil {
		var err error
		startupArgs, err = parseStartup(*strategy.Startup, true)
		if err != nil {
			return nil, errors.Wrapf(err, "parse startup failed: %s", *strategy.Startup)
		}
	}

	if startupArgs.Snaplen != nil {
		task.Capturer.Libpcap.Snaplen = lo.ToPtr(*startupArgs.Snaplen)
	}
	if startupArgs.Timeout != nil {
		task.Capturer.Libpcap.TimeoutMs = lo.ToPtr(int(*startupArgs.Timeout))
	}
	if isTrue(startupArgs.NoFilter) {
		allowNoFilter := func() bool {
			if item.typ != TaskTypeInterface {
				return true
			}
			if !slices.Contains([]string{PacketChannelType_GRE, PacketChannelType_VXLAN}, strategy.PacketChannelType) {
				return false
			}
			if startupArgs.BindDevice == nil {
				return false
			}
			if *startupArgs.BindDevice == item.nicName {
				return false
			}
			return true
		}()
		if !allowNoFilter {
			return nil, errors.Errorf("nofilter only allowed when bind_device is set and different from the snoop interface")
		}
	}
	task.Capturer.Libpcap.NotFilterOutputHosts = startupArgs.NoFilter

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
		output.Vxlan.BindDevice = startupArgs.BindDevice
		output.Vxlan.Pmtudisc = startupArgs.Pmtudisc
		if strategy.HasPacketSplit {
			output.Vxlan.Split = &worker.PacketSplitConfig{
				MaxPayloadSize: strategy.PacketSplitBytes,
			}
			if strategy.RecalculateChecksum {
				output.Vxlan.Split.RecalculateChecksum = lo.ToPtr(strategy.RecalculateChecksum)
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
		output.Gre.BindDevice = startupArgs.BindDevice
		output.Gre.Pmtudisc = startupArgs.Pmtudisc
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
		output.Zmq.Hwm = startupArgs.ZmqHwm
		if strategy.ZmqHeartbeatMs != nil {
			output.Zmq.HeartbeatMs = strategy.ZmqHeartbeatMs
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
	task.Capturer.Libpcap.Interface = item.nicName
	if item.netns != "" {
		task.Capturer.Libpcap.Netns = lo.ToPtr(item.netns)
	}
	return &task, nil
}

func (b *workerTaskBuilder) build() ([]*worker.TaskConfig, []error) {
	fingerprints := make(map[string]struct{})
	for _, task := range b.tasks {
		labels := task.FingerPrintLables()
		seq := 1
		for {
			fingerprint := common.LabelsToFingerprint(labels).UUID().String()
			_, exists := fingerprints[fingerprint]
			if !exists {
				fingerprints[fingerprint] = struct{}{}
				task.Fingerprint = lo.ToPtr(fingerprint)
				break
			}
			labels["_seq"] = fmt.Sprintf("%d", seq)
			seq++
		}
	}
	return b.tasks, b.warnings
}

func decodeContainerId(containerId string) (string, []string) {
	// 来源旧版本C++实现，支持多个连续的下划线
	parts := strings.FieldsFunc(containerId, func(r rune) bool {
		return r == '_'
	})
	if len(parts) == 0 {
		return "", nil
	}
	nics := parts[1:]
	if len(nics) == 0 {
		// 未指定nic，默认使用eth0
		nics = []string{"eth0"}
	}

	id := parts[0]
	i := strings.Index(id, "://")
	if i != -1 {
		// 处理类似 "docker://container_id" 的格式
		id = id[i+3:]
	}

	return id, nics
}

type TaskType int

const (
	TaskTypeInterface TaskType = iota + 1
	TaskTypeContainer
	TaskTypeKvmInstance
)

type taskItem struct {
	typ     TaskType
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
	Snaplen    *int
	Timeout    *int
	BindDevice *string
	Pmtudisc   *string
	ZmqHwm     *int
	NoFilter   *bool

	Priority    *bool // unused，非任务级别参数
	CpuAffinity *int  // unused，非任务级别参数
}

func parseStartup(startup string, ignoreUnknown bool) (*startupArgs, error) {
	args, err := splitArgs(startup)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	f := flag.NewFlagSet("", flag.ContinueOnError)
	snaplen := f.IntP("snaplen", "s", 0, "snaplen")
	timeout := f.IntP("timeout", "t", 0, "timeout")
	bindDevice := f.StringP("bind_device", "B", "", "bind device")
	pmtudisc := f.StringP("pmtudisc_option", "M", "", "select Path MTU Discovery option")
	zmqHwm := f.Int("zmq_hwm", 100, "ZMQ high watermark")
	noFilter := f.Bool("nofilter", false, "force no filter, you confirm that the snoop interface is different from the output interface")
	priority := f.BoolP("priority", "p", false, "set high priority mode")
	cpuAffinity := f.Int("cpu", -1, "set CPU affinity core")

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
	if f.Changed("bind_device") {
		res.BindDevice = bindDevice
	}
	if f.Changed("pmtudisc_option") {
		res.Pmtudisc = pmtudisc
	}
	if f.Changed("zmq_hwm") {
		res.ZmqHwm = zmqHwm
	}
	if f.Changed("nofilter") {
		res.NoFilter = noFilter
	}
	if f.Changed("priority") {
		res.Priority = priority
	}
	if f.Changed("cpu") {
		res.CpuAffinity = cpuAffinity
	}

	return res, nil
}

func isTrue(v *bool) bool {
	return v != nil && *v
}
