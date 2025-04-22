package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Netis/cloud-probe/cpdaemon/cmd/internal/asm"
)

func Test_Viper(t *testing.T) {
	vp := viper.New()
	vp.SetConfigFile("testdata/config.json")
	require.NoError(t, vp.ReadInConfig())

	vp.AutomaticEnv()
	vp.SetEnvPrefix(strings.ToUpper(asm.AppName))
	vp.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	asm.SetDefaults(vp)

	t.Setenv("CPDAEMON_LISTEN_HTTP_ADDRESS", "127.0.0.1")
	t.Setenv("CPDAEMON_LISTEN_HTTP_PORT", "21110")
	t.Setenv("CPDAEMON_TOOL_GET_CONTAINER_HOST_PID_SCRIPT", "get_container_host_pid.sh")

	assert.Equal(t, "127.0.0.1", vp.GetString(asm.VKey.Listen.Http.Address))
	assert.Equal(t, "21110", vp.GetString(asm.VKey.Listen.Http.Port))

	assert.Equal(t, "./bin/cpagent", vp.GetString(asm.VKey.Agent.Executable))

	assert.Equal(t, "get_container_host_pid.sh", vp.GetString(asm.VKey.Tool.GetContainerHostPidScript))
	assert.Equal(t, "", vp.GetString(asm.VKey.Tool.GetKvmInstancesScript))
	assert.Equal(t, "", vp.GetString(asm.VKey.Tool.GetKvmInstanceNicsScript))

	assert.Equal(t, "v1", vp.GetString(asm.VKey.Cgroup.Version))
	assert.Equal(t, "/sys/fs/cgroup", vp.GetString(asm.VKey.Cgroup.Root))
	assert.Equal(t, "cpagent", vp.GetString(asm.VKey.Cgroup.Hierarchy))

	assert.Equal(t, "https://127.0.0.1:48018", vp.GetString(asm.VKey.Cpm.BaseUrl))

	assert.Equal(t, 15*time.Second, vp.GetDuration(asm.VKey.Cpm.Client.Timeout))
	assert.Equal(t, 5*time.Second, vp.GetDuration(asm.VKey.Cpm.Client.DialTimeout))
	assert.Equal(t, 15*time.Second, vp.GetDuration(asm.VKey.Cpm.Client.ResponseHeaderTimeout))
	assert.Equal(t, 10, vp.GetInt(asm.VKey.Cpm.Client.MaxIdleConns))
	assert.Equal(t, 5, vp.GetInt(asm.VKey.Cpm.Client.MaxIdleConnsPerHost))

	assert.Equal(t, "cpdaemon-test", vp.GetString(asm.VKey.Cpm.Reg.Name))
	assert.Equal(t, "cpm-uuid.txt", vp.GetString(asm.VKey.Cpm.Reg.UuidFile))
	assert.Equal(t, "george-ali", vp.GetString(asm.VKey.Cpm.Reg.PlatformId))
	assert.Equal(t, "INSTANCE", vp.GetString(asm.VKey.Cpm.Reg.DeployEnv))
	assert.Equal(t, []string{"daemonset"}, vp.GetStringSlice(asm.VKey.Cpm.Reg.Labels))
	assert.Equal(t, []string{"eth0", "eth1"}, vp.GetStringSlice(asm.VKey.Cpm.Reg.IncludingNICs))
	assert.Equal(t, "test", vp.GetString(asm.VKey.Cpm.Reg.PodName))
	assert.Equal(t, "cloud-probe", vp.GetString(asm.VKey.Cpm.Reg.Namespace))
	assert.Equal(t, "test", vp.GetString(asm.VKey.Cpm.Reg.NodeName))

	assert.Equal(t, "INFO", vp.GetString(asm.VKey.Cpm.Agent.LogLevel))
	assert.Equal(t, "cpm-agent.json", vp.GetString(asm.VKey.Cpm.Agent.ConfigFile))
	assert.Equal(t, "cpm-agent.sock", vp.GetString(asm.VKey.Cpm.Agent.UnixSocket))
	assert.Equal(t, -1, vp.GetInt(asm.VKey.Cpm.Agent.CpuAffinity))
}
