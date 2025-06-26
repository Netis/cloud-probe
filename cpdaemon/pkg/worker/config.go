package worker

const (
	CapturerType_Libpcap = "libpcap"

	OutputType_Vxlan        = "vxlan"
	OutputType_Gre          = "gre"
	OutputType_Zmq          = "zmq"
	OutputType_File         = "file"
	OutputType_RotatingFile = "rotating_file"

	ReqPatternType_AUTO   = "auto"
	ReqPatternType_CUSTOM = "custom"
)

type Config struct {
	CpuAffinity *string       `json:"cpu_affinity,omitempty"`
	LogLevel    string        `json:"log_level"`
	Control     ControlConfig `json:"control"`
	Tasks       []TaskConfig  `json:"tasks"`
}

type ControlConfig struct {
	Type string             `json:"type"`
	Unix *ControlUnixConfig `json:"unix,omitempty"`
}

func (c ControlConfig) ConnectString() string {
	switch c.Type {
	case "unix":
		if c.Unix != nil {
			return "unix://" + c.Unix.Path
		}
		return "unix://"
	default:
		return ""
	}
}

type ControlUnixConfig struct {
	Path string `json:"path"`
}

type TaskConfig struct {
	ReqPattern *ReqPatternConfig `json:"req_pattern,omitempty"`
	Capturer   CapturerConfig    `json:"capturer"`
	Outputs    []OutputConfig    `json:"outputs"`
}

type ReqPatternConfig struct {
	Type   string                  `json:"type"`
	Custom *CustomReqPatternConfig `json:"custom,omitempty"`
}

type CustomReqPatternConfig struct {
	Pattern string `json:"pattern,omitempty"`
}

type CapturerConfig struct {
	Type    string         `json:"type"`
	Libpcap *LibpcapConfig `json:"libpcap,omitempty"`
}

type LibpcapConfig struct {
	Interface            string  `json:"interface"`
	Snaplen              *int    `json:"snaplen,omitempty"`
	Netns                *string `json:"netns,omitempty"`
	Bpf                  *string `json:"bpf,omitempty"`
	BufferSizeMB         *uint64 `json:"buffer_size_mb,omitempty"`
	TimeoutMs            *int    `json:"timeout_ms,omitempty"`
	NotFilterOutputHosts *bool   `json:"not_filter_output_hosts,omitempty"`
}

type OutputConfig struct {
	Type          string                    `json:"type"`
	RateLimitMbps *uint64                   `json:"rate_limit_mbps,omitempty"`
	Slice         *uint64                   `json:"slice,omitempty"`
	Vxlan         *VxlanOutputConfig        `json:"vxlan,omitempty"`
	Gre           *GreOutputConfig          `json:"gre,omitempty"`
	Zmq           *ZmqOutputConfig          `json:"zmq,omitempty"`
	File          *FileOutputConfig         `json:"file,omitempty"`
	RotatingFile  *RotatingFileOutputConfig `json:"rotating_file,omitempty"`
}

type VxlanOutputConfig struct {
	Host        string  `json:"host"`
	Port        *int32  `json:"port,omitempty"`
	CaptureTime *bool   `json:"capture_time,omitempty"`
	Vni1        *uint32 `json:"vni1,omitempty"`
	Vni2        *uint32 `json:"vni2,omitempty"`
	BindDevice  *string `json:"bind_device,omitempty"`
	Pmtudisc    *string `json:"pmtudisc,omitempty"`
}

type GreOutputConfig struct {
	Host       string  `json:"host"`
	ServiceTag *uint32 `json:"service_tag,omitempty"`
	BindDevice *string `json:"bind_device,omitempty"`
	Pmtudisc   *string `json:"pmtudisc,omitempty"`
}

type ZmqOutputConfig struct {
	Host       string  `json:"host"`
	Port       int32   `json:"port"`
	Hwm        *int    `json:"hwm,omitempty"`
	ServiceTag *uint32 `json:"service_tag,omitempty"`
	Uuid       string  `json:"uuid"`
}

type FileOutputConfig struct {
	Name string `json:"name"`
}

type RotatingFileOutputConfig struct {
	FileRoot        string `json:"file_root"`
	MaxFileInterval *int32 `json:"max_file_interval,omitempty"` // seconds
}
