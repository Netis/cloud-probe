package worker

import (
	"fmt"
	"math"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netis/cloud-probe/cpgolib/cpworker"
)

func init() {
	WorkerCmd.AddCommand(statsCmd)

	statsCmd.Flags().StringVar(&statsCfg.control, "control", "", "cpworker control connection string, example: unix:///var/run/cloud-probe/cpworker.sock")
	statsCmd.MarkFlagRequired("control")
}

var statsCfg struct {
	control string
}

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show worker stats",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		client, err := cpworker.NewClient(statsCfg.control)
		if err != nil {
			return err
		}
		defer client.Close()

		tm := time.NewTimer(0)
		defer tm.Stop()

		var lastStats *cpworker.StatsSummary
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-tm.C:
				stats, err := client.CollectStatsSummary(cmd.Context())
				if err != nil {
					return err
				}

				if lastStats != nil {
					t1 := time.Unix(stats.Time.Sec, stats.Time.Nsec)
					t2 := time.Unix(lastStats.Time.Sec, lastStats.Time.Nsec)
					if t1.After(t2) {
						fmt.Println("-------------------------------")
						printSummaryStats(stats, *lastStats)
					}
				}
				lastStats = &stats
				tm.Reset(2 * time.Second)
			}
		}
	},
}

func printSummaryStats(stats cpworker.StatsSummary, lastStats cpworker.StatsSummary) {
	headers := make([]string, 0, 12)
	row := make([]string, 0, len(headers))

	t1 := time.Unix(stats.Time.Sec, stats.Time.Nsec)
	t2 := time.Unix(lastStats.Time.Sec, lastStats.Time.Nsec)
	secs := t1.Sub(t2).Seconds()

	headers = append(headers, "Cap Bytes")
	diffCapBytes, isLess := stats.Capture.CapBytes.Sub(lastStats.Capture.CapBytes)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatBytesAndPerSec(diffCapBytes, secs))
	}

	headers = append(headers, "Cap Packets")
	diffCapPackets, isLess := stats.Capture.CapPackets.Sub(lastStats.Capture.CapPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffCapPackets, secs))
	}

	headers = append(headers, "Drop Packets")
	diffDropPackets, isLess := stats.Capture.DropPackets.Sub(lastStats.Capture.DropPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffDropPackets, secs))
	}

	headers = append(headers, "Ifdrop Packets")
	diffIfdropPackets, isLess := stats.Capture.IfdropPackets.Sub(lastStats.Capture.IfdropPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffIfdropPackets, secs))
	}

	headers = append(headers, "Fwd Bytes")
	diffFwdBytes, isLess := stats.Output.FwdBytes.Sub(lastStats.Output.FwdBytes)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatBytesAndPerSec(diffFwdBytes, secs))
	}

	headers = append(headers, "Fwd Packets")
	diffFwdPackets, isLess := stats.Output.FwdPackets.Sub(lastStats.Output.FwdPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffFwdPackets, secs))
	}

	headers = append(headers, "Direction Drop Bytes")
	diffDirectionDropBytes, isLess := stats.Output.DirectionDropBytes.Sub(lastStats.Output.DirectionDropBytes)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatBytesAndPerSec(diffDirectionDropBytes, secs))
	}

	headers = append(headers, "Direction Drop Packets")
	diffDirectionDropPackets, isLess := stats.Output.DirectionDropPackets.Sub(lastStats.Output.DirectionDropPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffDirectionDropPackets, secs))
	}

	headers = append(headers, "Error Drop Bytes")
	diffErrorDropBytes, isLess := stats.Output.ErrorDropBytes.Sub(lastStats.Output.ErrorDropBytes)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatBytesAndPerSec(diffErrorDropBytes, secs))
	}

	headers = append(headers, "Error Drop Packets")
	diffErrorDropPackets, isLess := stats.Output.ErrorDropPackets.Sub(lastStats.Output.ErrorDropPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffErrorDropPackets, secs))
	}

	headers = append(headers, "Ratelimit Drop Bytes")
	diffRatelimitDropBytes, isLess := stats.Output.RatelimitDropBytes.Sub(lastStats.Output.RatelimitDropBytes)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatBytesAndPerSec(diffRatelimitDropBytes, secs))
	}

	headers = append(headers, "Ratelimit Drop Packets")
	diffRatelimitDropPackets, isLess := stats.Output.RatelimitDropPackets.Sub(lastStats.Output.RatelimitDropPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffRatelimitDropPackets, secs))
	}

	maxHeaderLen := 0
	for _, h := range headers {
		if len(h) > maxHeaderLen {
			maxHeaderLen = len(h)
		}
	}

	for i, h := range headers {
		fmt.Printf("%-*s : %s\n", maxHeaderLen, h, row[i])
	}
}

func packetsStatsPerSec(stats cpworker.PacketsStats, secs float64) cpworker.PacketsStats {
	packets := uint64(float64(stats.Packets) / secs)
	peta := float64(stats.Peta) / secs
	petaInt := math.Trunc(peta)
	petaRem := peta - petaInt
	packets += uint64(petaRem * cpworker.PETA_IN_PACKETS)
	return cpworker.PacketsStats{
		Packets: packets,
		Peta:    uint64(petaInt),
	}
}

func bytesStatsPerSec(stats cpworker.BytesStats, secs float64) cpworker.BytesStats {
	bytes := uint64(float64(stats.Bytes) / secs)
	eib := float64(stats.Eib) / secs
	eibInt := math.Trunc(eib)
	eibRem := eib - eibInt
	bytes += uint64(eibRem * cpworker.EIB_IN_BYTES)
	return cpworker.BytesStats{
		Bytes: bytes,
		Eib:   uint64(eibInt),
	}
}

func formatPacketsStats(stats cpworker.PacketsStats) string {
	v := fmt.Sprintf("%d", stats.Packets)
	if stats.Peta != 0 {
		v = fmt.Sprintf("%d Peta, %s", stats.Peta, v)
	}
	return v
}

func formatPacketsAndPerSec(stats cpworker.PacketsStats, secs float64) string {
	perSec := packetsStatsPerSec(stats, secs)
	return fmt.Sprintf("%s; (%s / s)", formatPacketsStats(stats), formatPacketsStats(perSec))
}

func formatBytesStats(stats cpworker.BytesStats) string {
	v := formatBytes(stats.Bytes)
	if stats.Eib != 0 {
		v = fmt.Sprintf("%d EB, %s", stats.Eib, v)
	}
	return v
}

func formatBytesAndPerSec(stats cpworker.BytesStats, secs float64) string {
	perSec := bytesStatsPerSec(stats, secs)
	return fmt.Sprintf("%s; (%s / s)", formatBytesStats(stats), formatBytesStats(perSec))
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "KMGTPE"[exp])
}
