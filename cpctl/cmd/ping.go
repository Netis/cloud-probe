package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Netis/cloud-probe/cpgolib/cpworker"
)

var pingCfg struct {
	count    int
	interval time.Duration
	quiet    bool
}

func init() {
	rootCmd.AddCommand(pingCmd)

	f := pingCmd.Flags()
	f.IntVarP(&pingCfg.count, "count", "n", 0,
		"number of pings to send (0 = run forever)")
	f.DurationVarP(&pingCfg.interval, "interval", "i", 1*time.Second,
		"interval between pings")
	f.BoolVarP(&pingCfg.quiet, "quiet", "q", false,
		"suppress per-ping output, show only the summary")
}

var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Send ping RPCs to cpworker and report RTT",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireUnix(); err != nil {
			return err
		}
		client, err := cpworker.NewClientWithTimeout(unixConnStr(), Globals.Timeout)
		if err != nil {
			return err
		}
		defer client.Close()

		return runPing(cmd.Context(), client, os.Stdout, pingCfg.count, pingCfg.interval, pingCfg.quiet, Globals.Format, Globals.Unix)
	},
}

type pingSummary struct {
	Sent       int
	Received   int
	LossPct    float64
	MinMs      float64
	AvgMs      float64
	MaxMs      float64
	StddevMs   float64
	HasSamples bool
}

func runPing(ctx context.Context, client cpworker.Client, out io.Writer, count int, interval time.Duration, quiet bool, format, target string) error {
	if format == FormatText && !quiet {
		fmt.Fprintf(out, "PING cpworker (%s)\n", target)
	}

	tm := time.NewTimer(0)
	defer tm.Stop()

	rtts := make([]float64, 0, max(count, 16))
	sent := 0
	for {
		select {
		case <-ctx.Done():
			emitPingSummary(out, format, sent, rtts)
			return nil
		case <-tm.C:
			seq := sent
			sent++
			// Each ping gets its own timeout: --timeout bounds the per-RPC
			// wait, not the total run duration of the ping loop.
			callCtx, cancel := withRPCTimeout(ctx)
			r, err := client.Ping(callCtx)
			cancel()
			rttMs := float64(r.Rtt) / float64(time.Millisecond)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					emitPingSummary(out, format, sent-1, rtts)
					return nil
				}
				emitPingError(out, format, seq, err, quiet)
			} else {
				rtts = append(rtts, rttMs)
				if !quiet {
					emitPingSample(out, format, seq, rttMs, r.When)
				}
			}

			if count > 0 && sent >= count {
				emitPingSummary(out, format, sent, rtts)
				return nil
			}
			tm.Reset(interval)
		}
	}
}

type pingSampleRecord struct {
	Kind  string  `json:"kind"`
	Ts    string  `json:"ts"`
	Seq   int     `json:"seq"`
	RttMs float64 `json:"rtt_ms"`
}

type pingErrorRecord struct {
	Kind string `json:"kind"`
	Seq  int    `json:"seq"`
	Err  string `json:"err"`
}

type pingSummaryRecord struct {
	Kind     string  `json:"kind"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"loss_pct"`
	MinMs    float64 `json:"min_ms,omitempty"`
	AvgMs    float64 `json:"avg_ms,omitempty"`
	MaxMs    float64 `json:"max_ms,omitempty"`
	StddevMs float64 `json:"stddev_ms,omitempty"`
}

func emitPingSample(out io.Writer, format string, seq int, rttMs float64, when time.Time) {
	switch format {
	case FormatJSONL:
		_ = writeJSONL(out, pingSampleRecord{
			Kind:  "sample",
			Ts:    when.UTC().Format(time.RFC3339Nano),
			Seq:   seq,
			RttMs: rttMs,
		})
	default:
		fmt.Fprintf(out, "seq=%d time=%.2f ms\n", seq, rttMs)
	}
}

func emitPingError(out io.Writer, format string, seq int, err error, quiet bool) {
	if quiet {
		return
	}
	switch format {
	case FormatJSONL:
		_ = writeJSONL(out, pingErrorRecord{
			Kind: "error",
			Seq:  seq,
			Err:  err.Error(),
		})
	default:
		fmt.Fprintf(out, "seq=%d error: %v\n", seq, err)
	}
}

func emitPingSummary(out io.Writer, format string, sent int, rtts []float64) {
	s := computePingSummary(sent, rtts)
	switch format {
	case FormatJSONL:
		rec := pingSummaryRecord{
			Kind:     "summary",
			Sent:     s.Sent,
			Received: s.Received,
			LossPct:  s.LossPct,
		}
		if s.HasSamples {
			rec.MinMs = s.MinMs
			rec.AvgMs = s.AvgMs
			rec.MaxMs = s.MaxMs
			rec.StddevMs = s.StddevMs
		}
		_ = writeJSONL(out, rec)
		return
	default:
		fmt.Fprintln(out, "--- cpworker ping statistics ---")
		fmt.Fprintf(out, "%d transmitted, %d received, %.0f%% loss\n", s.Sent, s.Received, s.LossPct)
		if s.HasSamples {
			fmt.Fprintf(out, "rtt min/avg/max/stddev = %.2f/%.2f/%.2f/%.2f ms\n",
				s.MinMs, s.AvgMs, s.MaxMs, s.StddevMs)
		}
	}
}

// computePingSummary derives min/avg/max/stddev from collected RTTs.
// Pure function — separated for unit testing.
func computePingSummary(sent int, rtts []float64) pingSummary {
	s := pingSummary{Sent: sent, Received: len(rtts)}
	if sent > 0 {
		s.LossPct = float64(sent-len(rtts)) / float64(sent) * 100.0
	}
	if len(rtts) == 0 {
		return s
	}
	s.HasSamples = true
	s.MinMs = rtts[0]
	s.MaxMs = rtts[0]
	var sum float64
	for _, v := range rtts {
		if v < s.MinMs {
			s.MinMs = v
		}
		if v > s.MaxMs {
			s.MaxMs = v
		}
		sum += v
	}
	s.AvgMs = sum / float64(len(rtts))
	if len(rtts) > 1 {
		var sqSum float64
		for _, v := range rtts {
			d := v - s.AvgMs
			sqSum += d * d
		}
		s.StddevMs = math.Sqrt(sqSum / float64(len(rtts)))
	}
	return s
}

