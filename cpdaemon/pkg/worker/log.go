package worker

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"strings"
	"time"
)

type slogWriter struct {
	logger    *slog.Logger
	remainder []byte
}

func newSlogWriter(logger *slog.Logger) *slogWriter {
	return &slogWriter{logger: logger}
}

func (w *slogWriter) Write(p []byte) (n int, err error) {
	data := p
	if len(w.remainder) > 0 {
		data = append(w.remainder, p...)
	}
	w.remainder = nil

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(scanLines)

	for scanner.Scan() {
		line := scanner.Text()
		_, level, msg, ok := parseLogLine(line)
		if ok {
			w.logger.LogAttrs(
				context.Background(),
				level,
				msg,
			)
		} else {
			w.logger.Info("invalid cpworker log", slog.String("content", line))
		}
	}

	if scanner.Err() != nil {
		w.remainder = scanner.Bytes()
	}
	return len(p), nil
}

func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}

func scanLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		// We have a full newline-terminated line.
		return i + 1, dropCR(data[0:i]), nil
	}
	if atEOF {
		return 0, data, bufio.ErrFinalToken
	}
	// Request more data.
	return 0, nil, nil
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
