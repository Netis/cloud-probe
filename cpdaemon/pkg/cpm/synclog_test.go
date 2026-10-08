package cpm

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

func newSyncLogTestLogger() (*slog.Logger, *SyncLogBuffer) {
	buf := &SyncLogBuffer{}
	return slog.New(&SyncLogHandler{w: buf, level: slog.LevelDebug}), buf
}

func syncLogDetails(t *testing.T, buf *SyncLogBuffer) string {
	t.Helper()
	entries := buf.Clear()
	require.Len(t, entries, 1)
	return entries[0].Details
}

type redactedValue struct{}

func (redactedValue) LogValue() slog.Value { return slog.StringValue("redacted") }

func TestSyncLog_ErrorAttributesAreInlined(t *testing.T) {
	lg, buf := newSyncLogTestLogger()

	lg.Error("register loop error, will retry", slogx.Error(errors.New("cpm down")))

	assert.Equal(t, `msg="register loop error, will retry" error="cpm down"`, syncLogDetails(t, buf))
}

func TestSyncLog_NilErrorIsOmitted(t *testing.T) {
	lg, buf := newSyncLogTestLogger()

	lg.Info("done", slogx.Error(nil))

	assert.Equal(t, "msg=done", syncLogDetails(t, buf))
}

func TestSyncLog_LogValuerIsResolved(t *testing.T) {
	lg, buf := newSyncLogTestLogger()

	lg.Info("login", slog.Any("password", redactedValue{}))

	assert.Equal(t, "msg=login password=redacted", syncLogDetails(t, buf))
}

func TestSyncLog_GroupedAttributesAreQualified(t *testing.T) {
	t.Run("record group", func(t *testing.T) {
		lg, buf := newSyncLogTestLogger()
		lg.Info("started", slog.Group("worker", slog.Int("pid", 42)))
		assert.Equal(t, "msg=started worker.pid=42", syncLogDetails(t, buf))
	})

	t.Run("handler group", func(t *testing.T) {
		lg, buf := newSyncLogTestLogger()
		lg.WithGroup("mgr").With(slog.String("id", "a")).Info("started", slog.Int("n", 1))
		assert.Equal(t, "msg=started mgr.id=a mgr.n=1", syncLogDetails(t, buf))
	})

	t.Run("error inside group", func(t *testing.T) {
		lg, buf := newSyncLogTestLogger()
		lg.WithGroup("mgr").Error("failed", slogx.Error(errors.New("boom")))
		assert.Equal(t, "msg=failed mgr.error=boom", syncLogDetails(t, buf))
	})

	t.Run("empty group", func(t *testing.T) {
		lg, buf := newSyncLogTestLogger()
		lg.Info("started", slog.Group("worker"))
		assert.Equal(t, "msg=started", syncLogDetails(t, buf))
	})
}
