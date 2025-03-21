package slogx

import (
	"fmt"
	"log/slog"
)

func Error(err error) slog.Attr {
	if err == nil {
		return slog.Attr{}
	}
	return slog.Any("", errorValue{e: err})
}

type errorValue struct {
	e error
}

func (e errorValue) LogValue() slog.Value {
	as := make([]slog.Attr, 0, 2)

	basic := e.e.Error()
	as = append(as, slog.String("error", basic))

	switch e := e.e.(type) {
	case fmt.Formatter:
		verbose := fmt.Sprintf("%+v", e)
		if verbose != basic {
			// This is a rich error type, like those produced by
			// github.com/pkg/errors.
			as = append(as, slog.String("errorVerbose", verbose))
		}
	}
	return slog.GroupValue(as...)
}

const LoggerNameKey = "loggerName"

func LoggerName(name string) slog.Attr {
	return slog.String("loggerName", name)
}
