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
	"time"

	"github.com/spf13/cobra"

	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

const (
	FormatText  = "text"
	FormatJSONL = "jsonl"
)

type GlobalConfig struct {
	Unix    string
	Format  string
	Timeout time.Duration
}

var Globals = GlobalConfig{
	Format:  FormatText,
	Timeout: 3 * time.Second,
}

var initLoggerOnce sync.Once

var rootCmd = &cobra.Command{
	Use:           "cpctl",
	Short:         "Control utility for cpworker",
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		initLoggerOnce.Do(func() {
			hd := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				AddSource: true,
				Level:     slog.LevelInfo,
			})
			slog.SetDefault(slog.New(hd))
		})
		return NormalizeFormat(&Globals.Format)
	},
}

// NormalizeFormat collapses jsonl/ndjson aliases to the canonical "jsonl"
// and validates that the value is one of the supported formats.
func NormalizeFormat(format *string) error {
	switch strings.ToLower(*format) {
	case FormatText:
		*format = FormatText
	case FormatJSONL, "ndjson":
		*format = FormatJSONL
	default:
		return fmt.Errorf("invalid --format %q (text|jsonl, ndjson accepted as alias)", *format)
	}
	return nil
}

func RootCmd() *cobra.Command {
	return rootCmd
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVarP(&Globals.Unix, "unix", "u", "",
		"path to cpworker unix control socket, e.g. /var/run/cloud-probe/cpworker.sock")
	pf.StringVarP(&Globals.Format, "format", "f", FormatText,
		"output format: text|jsonl (ndjson accepted as alias for jsonl)")
	pf.DurationVarP(&Globals.Timeout, "timeout", "W", 3*time.Second,
		"per-RPC timeout")
}

// requireUnix returns an error if --unix was not set. Used by
// commands that must talk to a cpworker.
func requireUnix() error {
	if Globals.Unix == "" {
		return fmt.Errorf("--unix/-u is required (e.g. /var/run/cloud-probe/cpworker.sock)")
	}
	return nil
}

// unixConnStr wraps the raw socket path into the cpworker client's
// connection-string form.
func unixConnStr() string {
	return "unix://" + Globals.Unix
}

// withRPCTimeout derives a per-RPC context from the parent using the global
// --timeout. For single-shot commands the returned ctx covers the whole call;
// loop commands (ping, stats) should call this per iteration so --timeout
// applies to each RPC and not the total run duration.
func withRPCTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	if Globals.Timeout <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, Globals.Timeout)
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
