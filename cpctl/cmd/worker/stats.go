package worker

import (
	"cmp"
	"fmt"
	"math"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netis/cloud-probe/cpgolib/cpworker"
)

const (
	EIB_IN_BYTES    = 1024 * 1024 * 1024 * 1024 * 1024 * 1024 // 1 EiB = 2^60 bytes
	PETA_IN_PACKETS = 10000000000000000                       // 1 Peta = 10^16 packets
)

func init() {
	WorkerCmd.AddCommand(statsCmd)

	statsCmd.Flags().StringVarP(&statsCfg.socketPath, "unix-socket", "s", "", "unix socket path, example: /var/run/cloud-probe/cpworker.sock")
	statsCmd.MarkFlagRequired("unix-socket")
}

var statsCfg struct {
	socketPath string
}

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show agent stats",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		client, err := cpworker.NewClient(statsCfg.socketPath)
		if err != nil {
			return err
		}
		defer client.Close()

		tm := time.NewTimer(0)
		defer tm.Stop()

		var lastStats *summaryStats
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-tm.C:
				stats, err := client.CollectStats(cmd.Context())
				if err != nil {
					return err
				}
				sStats := newSummaryStats(stats)
				if lastStats != nil && sStats.Time.After(lastStats.Time) {
					fmt.Println("-------------------------------")
					printSummaryStats(sStats, *lastStats)
				}
				lastStats = &sStats
				tm.Reset(2 * time.Second)
			}
		}
	},
}

func printSummaryStats(stats summaryStats, lastStats summaryStats) {
	headers := make([]string, 0, 12)
	row := make([]string, 0, len(headers))

	secs := stats.Time.Sub(lastStats.Time).Seconds()

	headers = append(headers, "Cap Bytes")
	diffCapBytes, isLess := diffBytesStats(stats.CapBytes, lastStats.CapBytes)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatBytesAndPerSec(diffCapBytes, secs))
	}

	headers = append(headers, "Cap Packets")
	diffCapPackets, isLess := diffPacketsStats(stats.CapPackets, lastStats.CapPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffCapPackets, secs))
	}

	headers = append(headers, "Drop Packets")
	diffDropPackets, isLess := diffPacketsStats(stats.DropPackets, lastStats.DropPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffDropPackets, secs))
	}

	headers = append(headers, "Ifdrop Packets")
	diffIfdropPackets, isLess := diffPacketsStats(stats.IfdropPackets, lastStats.IfdropPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffIfdropPackets, secs))
	}

	headers = append(headers, "Fwd Bytes")
	diffFwdBytes, isLess := diffBytesStats(stats.FwdBytes, lastStats.FwdBytes)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatBytesAndPerSec(diffFwdBytes, secs))
	}

	headers = append(headers, "Fwd Packets")
	diffFwdPackets, isLess := diffPacketsStats(stats.FwdPackets, lastStats.FwdPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffFwdPackets, secs))
	}

	headers = append(headers, "Direction Drop Bytes")
	diffDirectionDropBytes, isLess := diffBytesStats(stats.DirectionDropBytes, lastStats.DirectionDropBytes)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatBytesAndPerSec(diffDirectionDropBytes, secs))
	}

	headers = append(headers, "Direction Drop Packets")
	diffDirectionDropPackets, isLess := diffPacketsStats(stats.DirectionDropPackets, lastStats.DirectionDropPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffDirectionDropPackets, secs))
	}

	headers = append(headers, "Error Drop Bytes")
	diffErrorDropBytes, isLess := diffBytesStats(stats.ErrorDropBytes, lastStats.ErrorDropBytes)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatBytesAndPerSec(diffErrorDropBytes, secs))
	}

	headers = append(headers, "Error Drop Packets")
	diffErrorDropPackets, isLess := diffPacketsStats(stats.ErrorDropPackets, lastStats.ErrorDropPackets)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatPacketsAndPerSec(diffErrorDropPackets, secs))
	}

	headers = append(headers, "Ratelimit Drop Bytes")
	diffRatelimitDropBytes, isLess := diffBytesStats(stats.RatelimitDropBytes, lastStats.RatelimitDropBytes)
	if isLess {
		row = append(row, "-")
	} else {
		row = append(row, formatBytesAndPerSec(diffRatelimitDropBytes, secs))
	}

	headers = append(headers, "Ratelimit Drop Packets")
	diffRatelimitDropPackets, isLess := diffPacketsStats(stats.RatelimitDropPackets, lastStats.RatelimitDropPackets)
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

type summaryStats struct {
	Time time.Time

	CapBytes   cpworker.BytesStats
	CapPackets cpworker.PacketsStats

	DropPackets   cpworker.PacketsStats
	IfdropPackets cpworker.PacketsStats

	FwdBytes   cpworker.BytesStats
	FwdPackets cpworker.PacketsStats

	DirectionDropBytes   cpworker.BytesStats
	DirectionDropPackets cpworker.PacketsStats

	ErrorDropBytes   cpworker.BytesStats
	ErrorDropPackets cpworker.PacketsStats

	RatelimitDropBytes   cpworker.BytesStats
	RatelimitDropPackets cpworker.PacketsStats
}

func newSummaryStats(stats cpworker.Stats) summaryStats {
	var summary summaryStats
	summary.Time = time.Unix(stats.Time.Sec, stats.Time.Nsec)

	for _, task := range stats.Tasks {
		summary.CapBytes = addBytesStats(summary.CapBytes, task.Capture.CapBytes)
		summary.CapPackets = addPacketsStats(summary.CapPackets, task.Capture.CapPackets)

		summary.DropPackets = addPacketsStats(summary.DropPackets, task.Capture.DropPackets)
		summary.IfdropPackets = addPacketsStats(summary.IfdropPackets, task.Capture.IfdropPackets)

		summary.FwdBytes = addBytesStats(summary.FwdBytes, task.Outputs[0].FwdBytes)
		summary.FwdPackets = addPacketsStats(summary.FwdPackets, task.Outputs[0].FwdPackets)

		for _, output := range task.Outputs {
			summary.DirectionDropBytes = addBytesStats(summary.DirectionDropBytes, output.DirectionDropBytes)
			summary.DirectionDropPackets = addPacketsStats(summary.DirectionDropPackets, output.DirectionDropPackets)

			summary.ErrorDropBytes = addBytesStats(summary.ErrorDropBytes, output.ErrorDropBytes)
			summary.ErrorDropPackets = addPacketsStats(summary.ErrorDropPackets, output.ErrorDropPackets)

			summary.RatelimitDropBytes = addBytesStats(summary.RatelimitDropBytes, output.RatelimitDropBytes)
			summary.RatelimitDropPackets = addPacketsStats(summary.RatelimitDropPackets, output.RatelimitDropPackets)
		}
	}

	return summary
}

func comparePacketsStats(stats cpworker.PacketsStats, lastStats cpworker.PacketsStats) int {
	return cmp.Or(
		cmp.Compare(stats.Peta, lastStats.Peta),
		cmp.Compare(stats.Packets, lastStats.Packets),
	)
}

func compareBytesStats(stats cpworker.BytesStats, lastStats cpworker.BytesStats) int {
	return cmp.Or(
		cmp.Compare(stats.Eib, lastStats.Eib),
		cmp.Compare(stats.Bytes, lastStats.Bytes),
	)
}

func addPacketsStats(stats cpworker.PacketsStats, lastStats cpworker.PacketsStats) cpworker.PacketsStats {
	packets := stats.Packets + lastStats.Packets
	peta := stats.Peta + lastStats.Peta
	if packets >= PETA_IN_PACKETS {
		peta++
		packets -= PETA_IN_PACKETS
	}
	return cpworker.PacketsStats{
		Packets: packets,
		Peta:    peta,
	}
}

func diffPacketsStats(stats cpworker.PacketsStats, lastStats cpworker.PacketsStats) (cpworker.PacketsStats, bool) {
	cmpRet := comparePacketsStats(stats, lastStats)
	isLess := cmpRet < 0

	xStats := stats
	yStats := lastStats
	if isLess {
		xStats = lastStats
		yStats = stats
	}

	peta := xStats.Peta - yStats.Peta
	var packets uint64
	if xStats.Packets < yStats.Packets {
		peta--
		packets = PETA_IN_PACKETS + xStats.Packets - yStats.Packets
	} else {
		packets = xStats.Packets - yStats.Packets
	}

	return cpworker.PacketsStats{
		Packets: packets,
		Peta:    peta,
	}, isLess
}

func addBytesStats(stats cpworker.BytesStats, lastStats cpworker.BytesStats) cpworker.BytesStats {
	bytes := stats.Bytes + lastStats.Bytes
	eib := stats.Eib + lastStats.Eib
	if bytes >= EIB_IN_BYTES {
		eib++
		bytes -= EIB_IN_BYTES
	}
	return cpworker.BytesStats{
		Bytes: bytes,
		Eib:   eib,
	}
}

func diffBytesStats(stats cpworker.BytesStats, lastStats cpworker.BytesStats) (cpworker.BytesStats, bool) {
	cmpRet := compareBytesStats(stats, lastStats)
	isLess := cmpRet < 0

	xStats := stats
	yStats := lastStats
	if isLess {
		xStats = lastStats
		yStats = stats
	}

	eib := xStats.Eib - yStats.Eib
	var bytes uint64
	if xStats.Bytes < yStats.Bytes {
		eib--
		bytes = EIB_IN_BYTES + xStats.Bytes - yStats.Bytes
	} else {
		bytes = xStats.Bytes - yStats.Bytes
	}

	return cpworker.BytesStats{
		Bytes: bytes,
		Eib:   eib,
	}, isLess
}

func packetsStatsPerSec(stats cpworker.PacketsStats, secs float64) cpworker.PacketsStats {
	packets := uint64(float64(stats.Packets) / secs)
	peta := float64(stats.Peta) / secs
	petaInt := math.Trunc(peta)
	petaRem := peta - petaInt
	packets += uint64(petaRem * PETA_IN_PACKETS)
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
	bytes += uint64(eibRem * EIB_IN_BYTES)
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
