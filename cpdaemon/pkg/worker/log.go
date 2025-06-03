package worker

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"time"
)

type lineOutput interface {
	Write(line string)
}

type slogOutput struct {
	logger *slog.Logger
}

func newSlogOutput(logger *slog.Logger) *slogOutput {
	return &slogOutput{logger: logger}
}

func (o *slogOutput) Write(line string) {
	_, level, msg, ok := parseLogLine(line)
	if ok {
		o.logger.LogAttrs(
			context.Background(),
			level,
			msg,
		)
	} else {
		o.logger.Info("invalid cpworker log", slog.String("content", line))
	}
}

const maxLineLength = 1024

type pipeWriter struct {
	rem []byte
	out lineOutput
}

func newPipeWriter(out lineOutput) *pipeWriter {
	return &pipeWriter{
		out: out,
		rem: make([]byte, 0, 256),
	}
}

func (w *pipeWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	for {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			w.addToRem(p)
			return n, nil
		}

		if i == 0 && len(w.rem) > 0 && w.rem[len(w.rem)-1] == '\r' {
			w.rem = w.rem[:len(w.rem)-1]
			w.addToRem(p[0:i])
		} else if i > 0 && p[i-1] == '\r' {
			w.addToRem(p[0 : i-1])
		} else {
			w.addToRem(p[0:i])
		}
		if len(w.rem) > 0 {
			w.out.Write(string(w.rem))
			w.rem = w.rem[:0]
		}
		p = p[i+1:]
	}
}

func (w *pipeWriter) addToRem(p []byte) {
	maxLen := max(cap(w.rem), maxLineLength)
	room := maxLen - len(w.rem)
	if room == 0 {
		return
	}
	if room < len(p) {
		p = p[:room]
	}
	w.rem = append(w.rem, p...)
	return
}

func parseLogLine(line string) (time.Time, slog.Level, string, bool) {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return time.Time{}, 0, "", false
	}
	tm, err := time.ParseInLocation("2006-01-02T15:04:05", parts[0], time.Local)
	if err != nil {
		return time.Time{}, 0, "", false
	}

	parts = strings.SplitN(strings.TrimSpace(parts[1]), " ", 2)
	if len(parts) != 2 {
		return time.Time{}, 0, "", false
	}

	var level slog.Level
	switch strings.ToLower(parts[0]) {
	case "trace":
		level = slog.LevelDebug
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	case "fatal":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	return tm, level, strings.TrimSpace(parts[1]), true
}
