package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/Netis/cloud-probe/cpctl/cmd/agent"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

var (
	verbose bool

	initLoggerOnce sync.Once
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	rootCmd.AddCommand(agent.AgentCmd)
}

var rootCmd = &cobra.Command{
	Use:           "cpctl",
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
