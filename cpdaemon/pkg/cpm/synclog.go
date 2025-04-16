package cpm

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	slogcommon "github.com/samber/slog-common"

	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

type SyncLogHandler struct {
	w      *SyncLogBuffer
	level  slog.Level
	attrs  []slog.Attr
	groups []string
}

func (h *SyncLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *SyncLogHandler) Handle(ctx context.Context, record slog.Record) error {
	content := h.convert(&record)
	return h.w.Write(ctx, record.Time, record.Level, content)
}

func (h *SyncLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SyncLogHandler{
		w:      h.w,
		level:  h.level,
		attrs:  slogcommon.AppendAttrsToGroup(h.groups, h.attrs, attrs...),
		groups: h.groups,
	}
}

func (h *SyncLogHandler) WithGroup(name string) slog.Handler {
	return &SyncLogHandler{
		w:      h.w,
		level:  h.level,
		attrs:  h.attrs,
		groups: append(h.groups, name),
	}
}

func (h *SyncLogHandler) convert(record *slog.Record) string {
	attrs := slogcommon.AppendRecordAttrsToAttrs(h.attrs, h.groups, record)
	parts := []string{"msg=" + record.Message}
	parts = append(parts, formatSyncLogAttrs("", attrs)...)
	return strings.Join(parts, " ")
}

func formatSyncLogAttrs(base string, attrs []slog.Attr) []string {
	result := make([]string, 0, len(attrs))
	for i := range attrs {
		attr := attrs[i]
		if attr.Value.Kind() == slog.KindGroup {
			result = append(result, formatSyncLogAttrs(base+attr.Key+".", attr.Value.Group())...)
		} else {
			result = append(result, attr.Key+"="+slogx.ValueToString(attr.Value))
		}
	}
	return result
}

const SyncLogBufSize = 100

type SyncLogBuffer struct {
	mu      sync.Mutex
	entries [SyncLogBufSize]LogEntry
	start   int
	end     int
}

func (b *SyncLogBuffer) Write(ctx context.Context, ts time.Time, level slog.Level, content string) error {
	entry := LogEntry{
		Timestamp:      ts.Unix(),
		MicroTimestamp: ts.UnixMicro() % 1e6,
		Level:          level.String(),
		Details:        content,
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[b.end] = entry
	b.end = (b.end + 1) % SyncLogBufSize
	if b.end == b.start {
		b.start = (b.start + 1) % SyncLogBufSize
	}
	return nil
}

func (b *SyncLogBuffer) Clear() []LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()

	var result []LogEntry
	start := b.start
	for start != b.end {
		result = append(result, b.entries[start])
		start = (start + 1) % SyncLogBufSize
	}

	b.start = 0
	b.end = 0
	clear(b.entries[:])
	return result
}
