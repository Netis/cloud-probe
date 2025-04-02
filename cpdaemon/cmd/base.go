package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Netis/cloud-probe/cpdaemon/cmd/internal/asm"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

var (
	verbose bool

	vpOnce         sync.Once
	vpErr          error
	initLoggerOnce sync.Once
)

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", "config.yml", "config file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	_ = rootCmd.MarkPersistentFlagFilename("config")
}

var rootCmd = &cobra.Command{
	Use:           "cpdaemon",
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// 防止单元测试多次初始化导致 DATA RACE
		initLoggerOnce.Do(func() {
			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			hd := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				AddSource: true,
				Level:     level,
			})
			lg := slog.New(hd)
			slog.SetDefault(lg)
		})
	},
}

func Execute() {
	var err error
	defer func() {
		if err == nil {
			return
		}
		slog.Error("fail", slogx.Error(err))
		os.Exit(1)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
		sig := <-c
		slog.Info("received signal", slog.String("signal", sig.String()))
		cancel()
	}()

	err = rootCmd.ExecuteContext(ctx)
}

func init() {
	vp := viper.GetViper()
	vp.AutomaticEnv()
	vp.SetEnvPrefix(strings.ToUpper(asm.AppName))
	vp.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
}

func getViper() (*viper.Viper, error) {
	vpOnce.Do(func() {
		flag := rootCmd.PersistentFlags().Lookup("config")
		if flag.Changed {
			path := flag.Value.String()
			viper.SetConfigFile(path)
			vpErr = errors.WithStack(viper.ReadInConfig())
			return
		}

		path, ok := os.LookupEnv(fmt.Sprintf("%s_CONFIG_FILE", strings.ToUpper(asm.AppName)))
		if ok {
			viper.SetConfigFile(path)
			vpErr = errors.WithStack(viper.ReadInConfig())
			return
		}

		viper.SetConfigName("config")
		viper.AddConfigPath(".")
		vpErr = errors.WithStack(viper.ReadInConfig())
		var e viper.ConfigFileNotFoundError
		if errors.As(vpErr, &e) {
			vpErr = nil
			return
		}
	})
	if vpErr != nil {
		return nil, vpErr
	}

	vp := viper.GetViper()
	asm.SetDefaults(vp)
	return vp, nil
}
