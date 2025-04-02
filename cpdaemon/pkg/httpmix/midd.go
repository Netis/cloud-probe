package httpmix

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/Netis/cloud-probe/cpgolib/slogx"
)

func Recoverer(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rvr := recover(); rvr != nil {
					if rvr == http.ErrAbortHandler {
						// we don't recover http.ErrAbortHandler so the response
						// to the client is aborted, this should not be logged
						panic(rvr)
					}

					stack := debug.Stack()
					if rErr, ok := rvr.(error); ok {
						logger.Error(
							"panic",
							slogx.Error(rErr),
							slog.String("stacktrace", string(stack)),
						)
					} else {
						logger.Error(
							"panic",
							slog.String("panic", fmt.Sprintf("%+v", rvr)),
							slog.String("stacktrace", string(stack)),
						)
					}

					w.WriteHeader(http.StatusInternalServerError)
					if rErr, ok := rvr.(error); ok {
						data, err := json.Marshal(ErrorResponse{Error: NewErrorInfo(rErr)})
						if err != nil {
							panic(err)
						}
						if _, err := w.Write(data); err != nil {
							logger.Error("write fail", slogx.Error(err))
						}
					}
				}
			}()
			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}

func Logger(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			t1 := time.Now()
			defer func() {
				logger.With(
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", ww.Status()),
					slog.Duration("elapsed", time.Since(t1)),
					slog.Int("size", ww.BytesWritten()),
				).Info("Served")
			}()
			next.ServeHTTP(ww, r)
		}
		return http.HandlerFunc(fn)
	}
}
