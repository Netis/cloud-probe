package cpm

import (
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/Netis/cloud-probe/cpgolib/cpworker"
)

const (
	ReqPatternType_AUTO   = "AUTO"
	ReqPatternType_CUSTOM = "CUSTOM"

	PacketChannelType_GRE   = "GRE"
	PacketChannelType_ZMQ   = "ZMQ"
	PacketChannelType_VXLAN = "VXLAN"
	PacketChannelType_FILE  = "FILE"

	ApiVersion_V1 = "v1"

	Status_Active   = "active"
	Status_Inactive = "inactive"
	Status_Error    = "error"

	SyncMode_Pull = "pull"
	SyncMode_Push = "push"

	DeployEnv_INSTANCE = "INSTANCE"
	DeployEnv_HOST     = "HOST"
)

var (
	SupportApiVersions = []string{
		ApiVersion_V1,
	}

	SupportPacketChannelTypes = []string{
		PacketChannelType_GRE,
		PacketChannelType_ZMQ,
		PacketChannelType_VXLAN,
		PacketChannelType_FILE,
	}
)

type HttpBodyError struct {
	StatusCode int
	Code       int
	Msg        string
}

func (e *HttpBodyError) Error() string {
	return fmt.Sprintf("http body error: status_code: %d, code: %d, msg: %s", e.StatusCode, e.Code, e.Msg)
}

type HttpRespError struct {
	StatusCode int
	Body       []byte
}

func (e *HttpRespError) Error() string {
	return fmt.Sprintf("http resp error: status_code: %d, body: %s", e.StatusCode, string(e.Body))
}

func NewHttpRespError(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &HttpRespError{StatusCode: resp.StatusCode, Body: []byte("read body error")}
	}

	return &HttpRespError{StatusCode: resp.StatusCode, Body: body}
}

type RegisterRequest struct {
	Name               string   `json:"name"`
	UUID               string   `json:"uuid"`
	Service            string   `json:"service"`
	NodeName           string   `json:"nodeName"`
	Namespace          string   `json:"namespace"`
	PodName            string   `json:"podName"`
	PlatformId         string   `json:"platformId"` // 必须参数，需要正确填写
	ApiVersion         string   `json:"apiVersion"`
	SupportApiVersions []string `json:"supportApiVersions"` // 必须参数，需要正确填写

	StartTimestamp      int64        `json:"startTimestamp"`
	StartMicroTimestamp int64        `json:"startMicroTimestamp"`
	ClientVersion       string       `json:"clientVersion"`
	Labels              []LabelEntry `json:"labels"`            // 不能为nil，可以为空数组
	NetworkInterfaces   []NicEntry   `json:"networkInterfaces"` // 不能为nil，可以为空数组
	DeployEnv           string       `json:"deployEnv"`         // 必须参数，需要正确填写
	PaUUID              string       `json:"paUUID"`            // 关键参数，如果为空，会由cpm自动生成
}

func (r *RegisterRequest) FixZero() error {
	if r.Labels == nil {
		r.Labels = []LabelEntry{}
	}
	if r.NetworkInterfaces == nil {
		r.NetworkInterfaces = []NicEntry{}
	}
	return nil
}

type RegisterResponse struct {
	Id                       int64  `json:"id"`
	PaUUID                   string `json:"paUUID"`
	Name                     string `json:"name"`
	RegisterRequestIpAddress string `json:"registerRequestIpAddress"`
	NodeName                 string `json:"nodeName"`
	PlatformId               string `json:"platformId"`
	StartTimestamp           int64  `json:"startTimestamp"`
	StartMicroTimestamp      int64  `json:"startMicroTimestamp"`
	SyncInterval             int32  `json:"syncInterval"`
	ClientVersion            string `json:"clientVersion"`
	// CreateTime               int64      `json:"createTime"` // ERROR: 有版本返回int64，有版本返回string
	NetworkInterfaces []NicEntry `json:"networkInterfaces"`
	Status            string     `json:"status"`
}

type SyncStrategyResult struct {
	Changed  bool
	Response *SyncStrategyResponse
}

type SyncStrategyResponse struct {
	Id           int64           `json:"id"`
	DaemonId     int64           `json:"daemonId"`
	Version      int32           `json:"version"`
	SyncInterval int32           `json:"syncInterval"`
	CpuLimit     *float64        `json:"cpuLimit"`
	MemLimit     *int64          `json:"memLimit"`
	Strategy     []StrategyEntry `json:"strategy"`

	MemFuseEnabled bool `json:"memFuseEnabled"`
	MemFused       bool `json:"memFused"`
}

// EffectiveMemLimitMb is the memory limit delivered by CPM, or defaultMb when CPM delivers none.
func (r *SyncStrategyResponse) EffectiveMemLimitMb(defaultMb uint64) uint64 {
	if r.MemLimit != nil && *r.MemLimit > 0 {
		return uint64(*r.MemLimit)
	}
	return defaultMb
}

func (r *SyncStrategyResponse) HasInstances() bool {
	for _, strategy := range r.Strategy {
		if len(strategy.InstanceNames) > 0 {
			return true
		}
	}
	return false
}

func (r *SyncStrategyResponse) NumItems(activeInstances []string) int {
	var n int
	for _, strategy := range r.Strategy {
		switch {
		case len(strategy.ContainerIds) > 0:
			n += len(strategy.ContainerIds)
		case len(strategy.InterfaceNames) > 0:
			n += len(strategy.InterfaceNames)
		case len(strategy.InstanceNames) > 0:
			for _, instanceName := range strategy.InstanceNames {
				if slices.Contains(activeInstances, instanceName) {
					n++
				}
			}
		}
	}
	return n
}

type StrategyEntry struct {
	InterfaceNames []string `json:"interfaceNames"`
	InstanceNames  []string `json:"instanceNames"`
	ContainerIds   []string `json:"containerIds"`

	Bpf              *string `json:"bpf"`
	SliceLen         *int32  `json:"sliceLen"`
	BuffLimit        *int64  `json:"buffLimit"`
	CapTime          *int32  `json:"capTime"`
	ForwardRateLimit *int32  `json:"forwardRateLimit"`

	HasServiceTag bool   `json:"hasServiceTag"`
	ServiceTag    *int32 `json:"serviceTag"`

	HasPacketSplit      bool   `json:"hasPacketSplit"`
	PacketSplitBytes    *int32 `json:"packetSplitBytes"`
	RecalculateChecksum bool   `json:"recalculateChecksum"`

	HasReqPattern  bool    `json:"hasReqPattern"`
	ReqPattern     *string `json:"reqPattern"`
	ReqPatternType *string `json:"reqPatternType"`

	ApiVersion *string `json:"apiVersion"`

	// example: "-s 65535 -t 0"
	Startup *string `json:"startup"`

	PacketChannelType string `json:"packetChannelType"`

	Address string `json:"address"`
	Port    *int32 `json:"port"`

	DumpDir      *string `json:"dumpDir"`
	DumpInterval *int32  `json:"dumpInterval"`

	// vni2
	HasObservationTag    bool     `json:"hasObservationTag"`
	ObservationDomainIds []uint32 `json:"observationDomainIds"`
	ObservationPointIds  []uint8  `json:"observationPointIds"`
	HasExtensionFlag     bool     `json:"hasExtensionFlag"`
	ExtensionFlag        *int8    `json:"extensionFlag"`

	ZmqHeartbeatMs *int32 `json:"zmqHeartbeatMs"`
}

type SyncMetricsRequest struct {
	Logs    []LogEntry    `json:"logs"`
	Metrics *MetricsEntry `json:"metrics"`
	Pid     *int32        `json:"pid"`
	MemFuse *MemFuseEntry `json:"memFuse,omitempty"`
}

// MemFuseEntry carries the memory fuse state. The pointer fields are sent only when fused, and CPM rejects a fused
// entry missing any of them, so a zero value must still be sent.
type MemFuseEntry struct {
	State          string  `json:"state"`
	Reason         *string `json:"reason,omitempty"`
	FusedTimestamp *int64  `json:"fusedTimestamp,omitempty"`
	NicBufferMb    uint64  `json:"nicBufferMb"`
	MinAvailableMb uint64  `json:"minAvailableMb"`
	MemLimitMb     *uint64 `json:"memLimitMb,omitempty"`
	MemAvailableMb *uint64 `json:"memAvailableMb,omitempty"`
	WorkerRssMb    *uint64 `json:"workerRssMb,omitempty"`
}

type NicEntry struct {
	Index         int      `json:"index"`
	Name          string   `json:"name"`
	Mac           string   `json:"mac"`
	Flags         int      `json:"flags"`
	Mtu           int      `json:"mtu"`
	InetAddresses []string `json:"inetAddresses"` // 不能为nil，可以为空数组
}

type LabelEntry struct {
	Value string `json:"value"`
}

type LogEntry struct {
	Timestamp      int64  `json:"logTimestamp"`
	MicroTimestamp int64  `json:"logMicroTimestamp"`
	Level          string `json:"logLevel"`
	Details        string `json:"logDetails"`
}

type MetricsEntry struct {
	SamplingTimestamp      int64   `json:"samplingTimestamp"`
	SamplingMicroTimestamp int64   `json:"samplingMicroTimestamp"`
	StartTime              int64   `json:"startTime"`
	CpuLoad                float64 `json:"cpuLoad"`
	CpuLoadRate            float64 `json:"cpuLoadRate"`
	MemUse                 uint64  `json:"memUse"`
	MemUseRate             float64 `json:"memUseRate"`
	CapBytes               uint64  `json:"capBytes"`
	CapPackets             uint64  `json:"capPackets"`
	CapDrop                uint64  `json:"capDrop"`
	FwdBytes               uint64  `json:"fwdBytes"`
	FwdPackets             uint64  `json:"fwdPackets"`
	CapBuff                uint64  `json:"capBuff"`
}

func (m *MetricsEntry) SetTaskStats(stats cpworker.StatsSummary) {
	// WARN: 存在溢出问题，需要CPM端配合处理
	m.CapBytes += stats.Capture.CapBytes.Bytes
	m.CapPackets += stats.Capture.CapPackets.Packets
	m.CapDrop += stats.Capture.DropPackets.Packets
	m.FwdBytes += stats.Output.FwdBytes.Bytes
	m.FwdPackets += stats.Output.FwdPackets.Packets
}
