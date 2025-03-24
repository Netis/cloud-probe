package agent

type TaskConfig struct {
	Interface  string         `json:"interface"`
	Snaplen    int            `json:"snaplen"`
	Netns      string         `json:"netns"`
	ReqPattern *ReqPattern    `json:"req_pattern,omitempty"`
	Capturer   CapturerConfig `json:"capturer"`
}

type ReqPattern struct {
	Type   string            `json:"type"`
	Custom *CustomReqPattern `json:"custom,omitempty"`
}

type CustomReqPattern struct {
	Patterns []string `json:"patterns"`
}

type CapturerConfig struct {
	Type    string         `json:"type"`
	Libpcap *LibpcapConfig `json:"libpcap,omitempty"`
}

type LibpcapConfig struct {
	Bpf          string `json:"bpf"`
	BufferSizeMB int    `json:"buffer_size_mb"`
	TimeoutMs    int    `json:"timeout_ms"`
}

type OutputConfig struct {
	Type          string `json:"type"`
	RateLimitMbps uint64 `json:"rate_limit_mbps"`
	Slice         int    `json:"slice"`
}

type VxlanOutputConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	CaptureTime bool   `json:"capture_time"`
	Vni1        uint32 `json:"vni1"`
	Vni2        uint32 `json:"vni2"`
	BindDevice  string `json:"bind_device"`
	Pmtudisc    string `json:"pmtudisc"`
}

type GreOutputConfig struct {
	Host       string `json:"host"`
	ServiceTag uint32 `json:"service_tag"`
	BindDevice string `json:"bind_device"`
	Pmtudisc   string `json:"pmtudisc"`
}

type ZmqOutputConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Hwm        int    `json:"hwm"`
	ServiceTag uint32 `json:"service_tag"`
}

type FileOutputConfig struct {
	Name string `json:"name"`
}
