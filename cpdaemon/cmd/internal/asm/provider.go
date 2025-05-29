package asm

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/cgroup"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/cpm"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/httpmix"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/tool"
	"github.com/Netis/cloud-probe/cpdaemon/pkg/worker"
	"github.com/Netis/cloud-probe/cpgolib/slogx"
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

func NewCpmClient(vp *viper.Viper) (*cpm.HttpClient, error) {
	baseUrl := vp.GetString(VKey.Cpm.BaseUrl)
	if baseUrl == "" {
		return nil, errors.New("cpm.baseUrl is missing")
	}
	return cpm.NewHttpClient(baseUrl, cpm.ClientConfig{
		Timeout:               vp.GetDuration(VKey.Cpm.Client.Timeout),
		DialTimeout:           vp.GetDuration(VKey.Cpm.Client.DialTimeout),
		ResponseHeaderTimeout: vp.GetDuration(VKey.Cpm.Client.ResponseHeaderTimeout),
		MaxIdleConns:          vp.GetInt(VKey.Cpm.Client.MaxIdleConns),
		MaxIdleConnsPerHost:   vp.GetInt(VKey.Cpm.Client.MaxIdleConnsPerHost),
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})
}

func NewCpmSyncer(ins *Instance, vp *viper.Viper, cpmClient *cpm.HttpClient) (*cpm.Syncer, error) {
	regName := vp.GetString(VKey.Cpm.Reg.Name)
	if regName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, errors.Wrapf(err, "get hostname failed")
		}
		regName = hostname
	}

	syncer, err := cpm.NewSyncer(
		cpmClient,
		cpm.WorkerConfig{
			PidFile:     vp.GetString(VKey.Cpm.Worker.PidFile),
			ConfigFile:  vp.GetString(VKey.Cpm.Worker.ConfigFile),
			Executable:  vp.GetString(VKey.Cpm.Worker.Executable),
			CpuAffinity: vp.GetInt(VKey.Cpm.Worker.CpuAffinity),
			LogLevel:    vp.GetString(VKey.Cpm.Worker.LogLevel),
			Control: worker.ControlConfig{
				Type: vp.GetString(VKey.Cpm.Worker.Control.Type),
				Unix: &worker.ControlUnixConfig{
					Path: filepath.Clean(vp.GetString(VKey.Cpm.Worker.Control.Unix.Path)),
				},
			},
			CgroupCfg: cgroup.CgroupCfg{
				Version:   vp.GetString(VKey.Cgroup.Version),
				Root:      vp.GetString(VKey.Cgroup.Root),
				Hierarchy: vp.GetString(VKey.Cgroup.Hierarchy),
			},
		},
		tool.Tool{
			GetContainerHostPidScript: vp.GetString(VKey.Tool.GetContainerHostPidScript),
			GetKvmInstancesScript:     vp.GetString(VKey.Tool.GetKvmInstancesScript),
			GetKvmInstanceNicsScript:  vp.GetString(VKey.Tool.GetKvmInstanceNicsScript),
		},
		cpm.SyncerConfig{
			RegCfg: cpm.RegConfig{
				Name:          regName,
				UuidFile:      vp.GetString(VKey.Cpm.Reg.UuidFile),
				NodeName:      vp.GetString(VKey.Cpm.Reg.NodeName),
				PlatformId:    vp.GetString(VKey.Cpm.Reg.PlatformId),
				DeployEnv:     vp.GetString(VKey.Cpm.Reg.DeployEnv),
				Labels:        vp.GetStringSlice(VKey.Cpm.Reg.Labels),
				IncludingNICs: vp.GetStringSlice(VKey.Cpm.Reg.IncludingNICs),

				PodName:   vp.GetString(VKey.Cpm.Reg.PodName),
				Namespace: vp.GetString(VKey.Cpm.Reg.Namespace),
			},
			RegRetryInterval:       vp.GetDuration(VKey.Cpm.Syncer.RegRetryInterval),
			SyncStrategyInterval:   vp.GetDuration(VKey.Cpm.Syncer.SyncStrategyInterval),
			SyncStrategyMaxRetries: vp.GetInt(VKey.Cpm.Syncer.SyncStrategyMaxRetries),
			SyncMetricInterval:     vp.GetDuration(VKey.Cpm.Syncer.SyncMetricInterval),
		})
	if err != nil {
		return nil, err
	}
	ins.Daemons = append(ins.Daemons, syncer.Run)
	return syncer, nil
}

type ServerEps struct {
	Mux *chi.Mux
}

func NewServerEps(
	mux *chi.Mux,
	_ *cpm.Syncer,
) (ServerEps, error) {
	return ServerEps{Mux: mux}, nil
}
