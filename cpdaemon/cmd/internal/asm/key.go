package asm

import (
	"reflect"
	"time"

	"github.com/spf13/viper"
)

const AppName = "cpdaemon"

var VKey = struct {
	Listen struct {
		Http struct {
			Address string `json:"address"`
			Port    string `json:"port"`
		} `json:"http"`
	} `json:"listen"`
	Log struct {
		Level  string `json:"level"`
		Output struct {
			Type         string `json:"type"`
			RotatingFile struct {
				FileName   string `json:"file_name"`
				MaxSize    string `json:"max_size"`
				MaxBackups string `json:"max_backups"`
				MaxAge     string `json:"max_age"`
			} `json:"rotating_file"`
		} `json:"output"`
	} `json:"log"`
	Tool struct {
		GetContainerHostPidScript string `json:"get_container_host_pid_script"`
		GetKvmInstancesScript     string `json:"get_kvm_instances_script"`
		GetKvmInstanceNicsScript  string `json:"get_kvm_instance_nics_script"`
	} `json:"tool"`
	Cgroup struct {
		Version   string `json:"version"`
		Root      string `json:"root"`
		Hierarchy string `json:"hierarchy"`
	} `json:"cgroup"`
	Cpm struct {
		BaseUrl string `json:"base_url"`
		Client  struct {
			Timeout               string `json:"timeout"`
			DialTimeout           string `json:"dial_timeout"`
			ResponseHeaderTimeout string `json:"response_header_timeout"`
			MaxIdleConns          string `json:"max_idle_conns"`
			MaxIdleConnsPerHost   string `json:"max_idle_conns_per_host"`
			TLS                   struct {
				Pkcs12CertFile     string `json:"pkcs12_cert_file"`
				Pkcs12CertPassword string `json:"pkcs12_cert_password"`
			} `json:"tls"`
		} `json:"client"`
		Syncer struct {
			RegRetryInterval       string `json:"reg_retry_interval"`
			SyncStrategyInterval   string `json:"sync_strategy_interval"`
			SyncStrategyMaxRetries string `json:"sync_strategy_max_retries"`
			SyncMetricInterval     string `json:"sync_metric_interval"`
		} `json:"syncer"`
		Reg struct {
			Name          string `json:"name"`
			PlatformId    string `json:"platform_id"`
			DeployEnv     string `json:"deploy_env"`
			Labels        string `json:"labels"`
			IncludingNICs string `json:"including_nics"`

			PodName   string `json:"pod_name"`
			Namespace string `json:"namespace"`
			NodeName  string `json:"node_name"`

			UuidFile string `json:"uuid_file"`
			UuidGen  struct {
				Type string `json:"type"`
				Env  struct {
					Keys string `json:"keys"`
				} `json:"env"`
			} `json:"uuid_gen"`
		} `json:"reg"`
		Worker struct {
			PidFile     string `json:"pid_file"`
			ConfigFile  string `json:"config_file"`
			Executable  string `json:"executable"`
			LogLevel    string `json:"log_level"`
			CpuAffinity string `json:"cpu_affinity"`
			Control     struct {
				Type string `json:"type"`
				Unix struct {
					Path string `json:"path"`
				} `json:"unix"`
			} `json:"control"`
		} `json:"worker"`
	} `json:"cpm"`
}{}

func SetDefaults(vp *viper.Viper) {
	vp.SetDefault(VKey.Listen.Http.Port, 9022)

	vp.SetDefault(VKey.Log.Level, "info")
	vp.SetDefault(VKey.Log.Output.Type, "stderr")
	vp.SetDefault(VKey.Log.Output.RotatingFile.MaxSize, 100)
	vp.SetDefault(VKey.Log.Output.RotatingFile.MaxBackups, 3)
	vp.SetDefault(VKey.Log.Output.RotatingFile.MaxAge, 30)

	vp.SetDefault(VKey.Cpm.Syncer.RegRetryInterval, 5*time.Second)
	vp.SetDefault(VKey.Cpm.Syncer.SyncStrategyInterval, 15*time.Second)
	vp.SetDefault(VKey.Cpm.Syncer.SyncStrategyMaxRetries, 3)
	vp.SetDefault(VKey.Cpm.Syncer.SyncMetricInterval, 15*time.Second)

	// 兼容旧的C++版本
	vp.SetDefault(VKey.Cpm.Reg.UuidFile, "/usr/local/bin/uuid")
	vp.SetDefault(VKey.Cpm.Reg.UuidGen.Type, "random")

	vp.SetDefault(VKey.Cpm.Worker.PidFile, "cpm-worker.pid")
	vp.SetDefault(VKey.Cpm.Worker.ConfigFile, "cpm-worker.json")
	vp.SetDefault(VKey.Cpm.Worker.Executable, "cpworker")
	vp.SetDefault(VKey.Cpm.Worker.LogLevel, "INFO")
	vp.SetDefault(VKey.Cpm.Worker.Control.Type, "unix")
	vp.SetDefault(VKey.Cpm.Worker.Control.Unix.Path, "cpm-worker.sock")
	vp.SetDefault(VKey.Cpm.Worker.CpuAffinity, -1)

	vp.SetDefault(VKey.Cpm.Client.Timeout, 15*time.Second)
	vp.SetDefault(VKey.Cpm.Client.DialTimeout, 5*time.Second)
	vp.SetDefault(VKey.Cpm.Client.ResponseHeaderTimeout, 15*time.Second)
	vp.SetDefault(VKey.Cpm.Client.MaxIdleConns, 10)
	vp.SetDefault(VKey.Cpm.Client.MaxIdleConnsPerHost, 5)

	vp.SetDefault(VKey.Cgroup.Version, "v1")
	vp.SetDefault(VKey.Cgroup.Root, "/sys/fs/cgroup")
	vp.SetDefault(VKey.Cgroup.Hierarchy, "cloud-probe")
}

func init() {
	fillKey(reflect.ValueOf(&VKey), "")
}

func fillKey(v reflect.Value, prefix string) {
	v = v.Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		ft := t.Field(i)
		fv := v.Field(i)
		switch ft.Type.Kind() {
		case reflect.String:
			name := ft.Name
			if v := ft.Tag.Get("json"); v != "" {
				name = v
			}
			fv.SetString(prefix + name)
		case reflect.Struct:
			name := ft.Name
			if v := ft.Tag.Get("json"); v != "" {
				name = v
			}
			fillKey(fv.Addr(), prefix+name+".")
		}
	}
}
