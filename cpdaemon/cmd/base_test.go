package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/Netis/cloud-probe/cpdaemon/cmd/internal/asm"
)

func Test_Viper(t *testing.T) {
	vp := viper.New()
	vp.AutomaticEnv()
	vp.SetEnvPrefix(strings.ToUpper(asm.AppName))
	vp.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	asm.SetDefaults(vp)

	t.Setenv("CPDAEMON_LISTEN_HTTP_ADDRESS", "127.0.0.1")
	t.Setenv("CPDAEMON_LISTEN_HTTP_PORT", "21110")
	t.Setenv("CPDAEMON_TOOL_GETCONTAINERHOSTPIDSCRIPT", "get_container_host_pid.sh")

	assert.Equal(t, vp.GetString(asm.VKey.Listen.Http.Address), "127.0.0.1")
	assert.Equal(t, vp.GetString(asm.VKey.Listen.Http.Port), "21110")
	assert.Equal(t, vp.GetString(asm.VKey.Tool.GetContainerHostPidScript), "get_container_host_pid.sh")
}
