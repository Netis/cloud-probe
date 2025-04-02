package slogx

import (
	"context"
	"log/slog"
)

var _ slog.Handler = (*MultipleHandler)(nil)

type MultipleHandler struct {
	handlers []slog.Handler
}

func Multiple(handlers ...slog.Handler) slog.Handler {
	return &MultipleHandler{
		handlers: handlers,
	}
}

func (h *MultipleHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for i := range h.handlers {
		if h.handlers[i].Enabled(ctx, l) {
			return true
		}
	}

	return false
}

func (h *MultipleHandler) Handle(ctx context.Context, r slog.Record) error {
	for i := range h.handlers {
		if h.handlers[i].Enabled(ctx, r.Level) {
			if err := h.handlers[i].Handle(ctx, r.Clone()); err != nil {
				return err
			}
		}
	}

	return nil
}

func (h *MultipleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i := range h.handlers {
		handlers[i] = h.handlers[i].WithAttrs(attrs)
	}
	return Multiple(handlers...)
}

func (h *MultipleHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i := range h.handlers {
		handlers[i] = h.handlers[i].WithGroup(name)
	}
	return Multiple(handlers...)
}
