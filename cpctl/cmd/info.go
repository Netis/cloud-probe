package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netis/cloud-probe/cpgolib/cpworker"
)

func init() {
	rootCmd.AddCommand(infoCmd)
}

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show cpworker process info (version, pid, uptime, config_path, working_dir)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireUnix(); err != nil {
			return err
		}
		ctx, cancel := withRPCTimeout(cmd.Context())
		defer cancel()

		client, err := cpworker.NewClientWithTimeout(unixConnStr(), Globals.Timeout)
		if err != nil {
			return err
		}
		defer client.Close()

		info, err := client.Info(ctx)
		if err != nil {
			return err
		}
		return emitInfo(os.Stdout, info, Globals.Format)
	},
}

// infoRecord is the jsonl shape of `cpctl info` (docs/REFACTOR-CPCTL.md §6.3).
type infoRecord struct {
	Version        string `json:"version"`
	Pid            int    `json:"pid"`
	UptimeSec      int64  `json:"uptime_sec"`
	ConfigPath     string `json:"config_path"`
	WorkingDir     string `json:"working_dir"`
	LogDestination string `json:"log_destination"`
	StartedAt      string `json:"started_at"`
}

func emitInfo(out io.Writer, info cpworker.InfoSummary, format string) error {
	switch format {
	case FormatJSONL:
		return writeJSONL(out, infoRecord{
			Version:        info.Version,
			Pid:            info.Pid,
			UptimeSec:      info.UptimeSec,
			ConfigPath:     info.ConfigPath,
			WorkingDir:     info.WorkingDir,
			LogDestination: info.LogDestination,
			StartedAt:      info.StartedAt().UTC().Format(time.RFC3339),
		})
	default:
		uptime := time.Duration(info.UptimeSec) * time.Second
		fmt.Fprintf(out, "version          : %s\n", info.Version)
		fmt.Fprintf(out, "pid              : %d\n", info.Pid)
		fmt.Fprintf(out, "uptime           : %s (%d sec)\n", uptime, info.UptimeSec)
		fmt.Fprintf(out, "started_at       : %s\n", info.StartedAt().Format(time.RFC3339))
		fmt.Fprintf(out, "config_path      : %s\n", info.ConfigPath)
		fmt.Fprintf(out, "working_dir      : %s\n", info.WorkingDir)
		fmt.Fprintf(out, "log_destination  : %s\n", info.LogDestination)
		return nil
	}
}
