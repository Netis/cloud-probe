package asm

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"reflect"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/httpmix"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/slogx"
)

func (sg Singleton) Mux() *chi.Mux {
	v, ok := sg[reflect.TypeOf(new(*chi.Mux))]
	if !ok {
		return nil
	}
	return v.(*chi.Mux)
}

func GetMux(ins *Instance) (*chi.Mux, error) {
	return Build2(ins.Sg, func() (*chi.Mux, error) {
		return NewMux()
	})
}

func NewMux() (*chi.Mux, error) {
	lg := slog.Default().With(slogx.LoggerName("http"))
	r := chi.NewRouter()
	r.Use(
		httpmix.Logger(lg.With(slogx.LoggerName("access"))),
		httpmix.Recoverer(lg.With(slogx.LoggerName("recover"))),
		middleware.RealIP,
	)
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			lg.Error("write health response error", slogx.Error(err))
		}
	})

	r.Mount("/debug/pprof/", http.HandlerFunc(pprof.Index))
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)

	return r, nil
}

func (ins *Instance) ListenHTTP(
	vp *viper.Viper,
	mux *chi.Mux,
) error {
	lg := slog.With(slogx.LoggerName("asm"))

	addr := net.JoinHostPort(vp.GetString(VKey.Listen.Http.Address), vp.GetString(VKey.Listen.Http.Port))
	server := http.Server{
		Addr:     addr,
		Handler:  mux,
		ErrorLog: slog.NewLogLogger(lg.With(slogx.LoggerName("http")).Handler(), slog.LevelError),
	}

	ins.Daemons = append(ins.Daemons,
		func(ctx context.Context) error {
			lg.Info("Listening and serving HTTP", slog.String("addr", addr))
			err := server.ListenAndServe()
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return errors.WithStack(err)
		},
		func(ctx context.Context) error {
			<-ctx.Done()
			lg.Info("http closing")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := server.Shutdown(ctx)
			if err == nil {
				return nil
			}

			lg.Info("shutdown timeout", slogx.Error(err))
			err = server.Close()
			if err != nil {
				lg.Info("close", slogx.Error(err))
			}
			return nil
		},
	)

	return nil
}

type ServerEps struct {
	Mux *chi.Mux
}

func NewServerEps(
	mux *chi.Mux,
) (ServerEps, error) {
	return ServerEps{Mux: mux}, nil
}
