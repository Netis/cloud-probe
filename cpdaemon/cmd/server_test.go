package cmd

import (
	"context"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Netis/cloud-probe/cpdaemon/cmd/internal/asm"
)

func Test_runSvr(t *testing.T) {
	vp := viper.GetViper()
	asm.SetDefaults(vp)
	vp.Set(asm.VKey.Cpm.BaseUrl, "https://127.0.0.1:48018")
	vp.Set(asm.VKey.Cpm.Reg.PlatformId, "test")
	vp.Set(asm.VKey.Cpm.Reg.DeployEnv, "INSTANCE")
	vp.Set(asm.VKey.Cpm.Reg.UuidFile, filepath.Join(t.TempDir(), "uuid"))

	ctx, cancel := context.WithCancel(context.Background())
	err := runSvr(ctx, vp, func(ins *asm.Instance) {
		assert.NotNil(t, ins.Sg.Mux())

		got := lo.Map(ins.Daemons, func(fn asm.Daemon, _ int) string {
			return runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
		})
		assert.Equal(t, []string{
			"github.com/Netis/cloud-probe/cpdaemon/pkg/cpm.(*Syncer).Run-fm",
			"github.com/Netis/cloud-probe/cpdaemon/cmd/internal/asm.(*Instance).ListenHTTP.func1",
			"github.com/Netis/cloud-probe/cpdaemon/cmd/internal/asm.(*Instance).ListenHTTP.func2",
		}, got)

		time.AfterFunc(time.Second, cancel)
	})
	require.NoError(t, err)
}
