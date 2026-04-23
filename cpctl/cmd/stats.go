package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netis/cloud-probe/cpgolib/cpworker"
)

var statsCfg struct {
	count    int
	interval time.Duration
}

func init() {
	rootCmd.AddCommand(statsCmd)

	f := statsCmd.Flags()
	f.IntVarP(&statsCfg.count, "count", "n", 0,
		"number of samples (0 = run forever)")
	f.DurationVarP(&statsCfg.interval, "interval", "i", 2*time.Second,
		"interval between samples")
}

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show cpworker stats (raw at -n=1, rates at -n>=2 or -n=0)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireUnix(); err != nil {
			return err
		}
		client, err := cpworker.NewClientWithTimeout(unixConnStr(), Globals.Timeout)
		if err != nil {
			return err
		}
		defer client.Close()

		return runStats(cmd.Context(), client, os.Stdout, statsCfg.count, statsCfg.interval, Globals.Format)
	},
}

// runStats is the testable core: it polls the client, formats output, and
// implements the (c) behavior — raw counters at count==1, diffs/rates when
// count>=2 or count==0 (forever).
func runStats(ctx context.Context, client cpworker.Client, out io.Writer, count int, interval time.Duration, format string) error {
	rawOnly := count == 1
	tm := time.NewTimer(0)
	defer tm.Stop()

	var lastStats *cpworker.StatsSummary
	emitted := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tm.C:
			callCtx, cancel := withRPCTimeout(ctx)
			stats, err := client.CollectStatsSummary(callCtx)
			cancel()
			if err != nil {
				return err
			}

			if rawOnly {
				if err := emitStatsRaw(out, stats, format); err != nil {
					return err
				}
				return nil
			}

			if lastStats != nil {
				t1 := time.Unix(stats.Time.Sec, stats.Time.Nsec)
				t2 := time.Unix(lastStats.Time.Sec, lastStats.Time.Nsec)
				if t1.After(t2) {
					if err := emitStatsDiff(out, stats, *lastStats, format); err != nil {
						return err
					}
					emitted++
				}
			}
			lastStats = &stats

			if count > 0 && emitted >= count-1 {
				return nil
			}
			tm.Reset(interval)
		}
	}
}

// statsRecord is the jsonl shape for one stats sample.
type statsRecord struct {
	Ts        string         `json:"ts"`
	Sample    string         `json:"sample"` // "raw" or "rate"
	IntervalS *float64       `json:"interval_sec,omitempty"`
	Counters  map[string]any `json:"counters"`
	Rates     map[string]any `json:"rates,omitempty"`
}

func emitStatsRaw(out io.Writer, s cpworker.StatsSummary, format string) error {
	switch format {
	case FormatJSONL:
		rec := statsRecord{
			Ts:       time.Unix(s.Time.Sec, s.Time.Nsec).UTC().Format(time.RFC3339Nano),
			Sample:   "raw",
			Counters: countersMap(s),
		}
		return writeJSONL(out, rec)
	default:
		printRawText(out, s)
		return nil
	}
}

func emitStatsDiff(out io.Writer, s, last cpworker.StatsSummary, format string) error {
	t1 := time.Unix(s.Time.Sec, s.Time.Nsec)
	t2 := time.Unix(last.Time.Sec, last.Time.Nsec)
	secs := t1.Sub(t2).Seconds()

	switch format {
	case FormatJSONL:
		rec := statsRecord{
			Ts:        t1.UTC().Format(time.RFC3339Nano),
			Sample:    "rate",
			IntervalS: &secs,
			Counters:  countersMap(s),
			Rates:     ratesMap(s, last, secs),
		}
		return writeJSONL(out, rec)
	default:
		fmt.Fprintln(out, "-------------------------------")
		printSummaryStats(out, s, last)
		return nil
	}
}

func writeJSONL(out io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := out.Write(append(data, '\n')); err != nil {
		return err
	}
	if f, ok := out.(*os.File); ok {
		_ = f.Sync()
	}
	return nil
}

// countersMap flattens StatsSummary's cumulative counters for jsonl output.
func countersMap(s cpworker.StatsSummary) map[string]any {
	return map[string]any{
		"cap_bytes":              bytesAsJSON(s.Capture.CapBytes),
		"cap_packets":            packetsAsJSON(s.Capture.CapPackets),
		"drop_packets":           packetsAsJSON(s.Capture.DropPackets),
		"ifdrop_packets":         packetsAsJSON(s.Capture.IfdropPackets),
		"fwd_bytes":              bytesAsJSON(s.Output.FwdBytes),
		"fwd_packets":            packetsAsJSON(s.Output.FwdPackets),
		"direction_drop_bytes":   bytesAsJSON(s.Output.DirectionDropBytes),
		"direction_drop_packets": packetsAsJSON(s.Output.DirectionDropPackets),
		"error_drop_bytes":       bytesAsJSON(s.Output.ErrorDropBytes),
		"error_drop_packets":     packetsAsJSON(s.Output.ErrorDropPackets),
		"ratelimit_drop_bytes":   bytesAsJSON(s.Output.RatelimitDropBytes),
		"ratelimit_drop_packets": packetsAsJSON(s.Output.RatelimitDropPackets),
	}
}

func ratesMap(s, last cpworker.StatsSummary, secs float64) map[string]any {
	rates := map[string]any{}
	addBytesRate := func(name string, cur, prev cpworker.BytesStats) {
		diff, isLess := cur.Sub(prev)
		if isLess {
			rates[name] = nil
			return
		}
		rates[name] = bytesAsJSON(bytesStatsPerSec(diff, secs))
	}
	addPacketsRate := func(name string, cur, prev cpworker.PacketsStats) {
		diff, isLess := cur.Sub(prev)
		if isLess {
			rates[name] = nil
			return
		}
		rates[name] = packetsAsJSON(packetsStatsPerSec(diff, secs))
	}

	addBytesRate("cap_bytes_per_sec", s.Capture.CapBytes, last.Capture.CapBytes)
	addPacketsRate("cap_packets_per_sec", s.Capture.CapPackets, last.Capture.CapPackets)
	addPacketsRate("drop_packets_per_sec", s.Capture.DropPackets, last.Capture.DropPackets)
	addPacketsRate("ifdrop_packets_per_sec", s.Capture.IfdropPackets, last.Capture.IfdropPackets)
	addBytesRate("fwd_bytes_per_sec", s.Output.FwdBytes, last.Output.FwdBytes)
	addPacketsRate("fwd_packets_per_sec", s.Output.FwdPackets, last.Output.FwdPackets)
	addBytesRate("direction_drop_bytes_per_sec", s.Output.DirectionDropBytes, last.Output.DirectionDropBytes)
	addPacketsRate("direction_drop_packets_per_sec", s.Output.DirectionDropPackets, last.Output.DirectionDropPackets)
	addBytesRate("error_drop_bytes_per_sec", s.Output.ErrorDropBytes, last.Output.ErrorDropBytes)
	addPacketsRate("error_drop_packets_per_sec", s.Output.ErrorDropPackets, last.Output.ErrorDropPackets)
	addBytesRate("ratelimit_drop_bytes_per_sec", s.Output.RatelimitDropBytes, last.Output.RatelimitDropBytes)
	addPacketsRate("ratelimit_drop_packets_per_sec", s.Output.RatelimitDropPackets, last.Output.RatelimitDropPackets)
	return rates
}

func bytesAsJSON(b cpworker.BytesStats) map[string]uint64 {
	return map[string]uint64{"bytes": b.Bytes, "eib": b.Eib}
}

func packetsAsJSON(p cpworker.PacketsStats) map[string]uint64 {
	return map[string]uint64{"packets": p.Packets, "peta": p.Peta}
}

func printRawText(out io.Writer, s cpworker.StatsSummary) {
	rows := []struct {
		header string
		value  string
	}{
		{"Cap Bytes", formatBytesStats(s.Capture.CapBytes)},
		{"Cap Packets", formatPacketsStats(s.Capture.CapPackets)},
		{"Drop Packets", formatPacketsStats(s.Capture.DropPackets)},
		{"Ifdrop Packets", formatPacketsStats(s.Capture.IfdropPackets)},
		{"Fwd Bytes", formatBytesStats(s.Output.FwdBytes)},
		{"Fwd Packets", formatPacketsStats(s.Output.FwdPackets)},
		{"Direction Drop Bytes", formatBytesStats(s.Output.DirectionDropBytes)},
		{"Direction Drop Packets", formatPacketsStats(s.Output.DirectionDropPackets)},
		{"Error Drop Bytes", formatBytesStats(s.Output.ErrorDropBytes)},
		{"Error Drop Packets", formatPacketsStats(s.Output.ErrorDropPackets)},
		{"Ratelimit Drop Bytes", formatBytesStats(s.Output.RatelimitDropBytes)},
		{"Ratelimit Drop Packets", formatPacketsStats(s.Output.RatelimitDropPackets)},
	}
	maxLen := 0
	for _, r := range rows {
		if len(r.header) > maxLen {
			maxLen = len(r.header)
		}
	}
	for _, r := range rows {
		fmt.Fprintf(out, "%-*s : %s\n", maxLen, r.header, r.value)
	}
}

func printSummaryStats(out io.Writer, stats cpworker.StatsSummary, lastStats cpworker.StatsSummary) {
	headers := make([]string, 0, 12)
	row := make([]string, 0, 12)

	t1 := time.Unix(stats.Time.Sec, stats.Time.Nsec)
	t2 := time.Unix(lastStats.Time.Sec, lastStats.Time.Nsec)
	secs := t1.Sub(t2).Seconds()

	addBytes := func(name string, cur, prev cpworker.BytesStats) {
		headers = append(headers, name)
		diff, isLess := cur.Sub(prev)
		if isLess {
			row = append(row, "-")
		} else {
			row = append(row, formatBytesAndPerSec(diff, secs))
		}
	}
	addPackets := func(name string, cur, prev cpworker.PacketsStats) {
		headers = append(headers, name)
		diff, isLess := cur.Sub(prev)
		if isLess {
			row = append(row, "-")
		} else {
			row = append(row, formatPacketsAndPerSec(diff, secs))
		}
	}

	addBytes("Cap Bytes", stats.Capture.CapBytes, lastStats.Capture.CapBytes)
	addPackets("Cap Packets", stats.Capture.CapPackets, lastStats.Capture.CapPackets)
	addPackets("Drop Packets", stats.Capture.DropPackets, lastStats.Capture.DropPackets)
	addPackets("Ifdrop Packets", stats.Capture.IfdropPackets, lastStats.Capture.IfdropPackets)
	addBytes("Fwd Bytes", stats.Output.FwdBytes, lastStats.Output.FwdBytes)
	addPackets("Fwd Packets", stats.Output.FwdPackets, lastStats.Output.FwdPackets)
	addBytes("Direction Drop Bytes", stats.Output.DirectionDropBytes, lastStats.Output.DirectionDropBytes)
	addPackets("Direction Drop Packets", stats.Output.DirectionDropPackets, lastStats.Output.DirectionDropPackets)
	addBytes("Error Drop Bytes", stats.Output.ErrorDropBytes, lastStats.Output.ErrorDropBytes)
	addPackets("Error Drop Packets", stats.Output.ErrorDropPackets, lastStats.Output.ErrorDropPackets)
	addBytes("Ratelimit Drop Bytes", stats.Output.RatelimitDropBytes, lastStats.Output.RatelimitDropBytes)
	addPackets("Ratelimit Drop Packets", stats.Output.RatelimitDropPackets, lastStats.Output.RatelimitDropPackets)

	maxHeaderLen := 0
	for _, h := range headers {
		if len(h) > maxHeaderLen {
			maxHeaderLen = len(h)
		}
	}
	for i, h := range headers {
		fmt.Fprintf(out, "%-*s : %s\n", maxHeaderLen, h, row[i])
	}
}

func packetsStatsPerSec(stats cpworker.PacketsStats, secs float64) cpworker.PacketsStats {
	if secs <= 0 {
		return stats
	}
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
	if secs <= 0 {
		return stats
	}
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
