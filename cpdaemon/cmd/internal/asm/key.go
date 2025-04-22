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
	Agent struct {
		Executable string `json:"executable"`
	} `json:"agent"`
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
			Pkcs12CertFile        string `json:"pkcs12_cert_file"`
			Pkcs12CertPassword    string `json:"pkcs12_cert_password"`
		} `json:"client"`
		Reg struct {
			Name          string `json:"name"`
			UuidFile      string `json:"uuid_file"`
			PlatformId    string `json:"platform_id"`
			DeployEnv     string `json:"deploy_env"`
			Labels        string `json:"labels"`
			IncludingNICs string `json:"including_nics"`

			PodName   string `json:"pod_name"`
			Namespace string `json:"namespace"`
			NodeName  string `json:"node_name"`
		} `json:"reg"`
		Agent struct {
			LogLevel    string `json:"log_level"`
			UnixSocket  string `json:"unix_socket"`
			ConfigFile  string `json:"config_file"`
			CpuAffinity string `json:"cpu_affinity"`
		} `json:"agent"`
	} `json:"cpm"`
}{}

func SetDefaults(vp *viper.Viper) {
	vp.SetDefault(VKey.Listen.Http.Port, 9022)

	vp.SetDefault(VKey.Agent.Executable, "cpagent")

	// 兼容旧的C++版本
	vp.SetDefault(VKey.Cpm.Reg.UuidFile, "/usr/local/bin/uuid")

	vp.SetDefault(VKey.Cpm.Agent.LogLevel, "INFO")
	vp.SetDefault(VKey.Cpm.Agent.UnixSocket, "cpm-agent.sock")
	vp.SetDefault(VKey.Cpm.Agent.ConfigFile, "cpm-agent.json")
	vp.SetDefault(VKey.Cpm.Agent.CpuAffinity, -1)

	vp.SetDefault(VKey.Cpm.Client.Timeout, 15*time.Second)
	vp.SetDefault(VKey.Cpm.Client.DialTimeout, 5*time.Second)
	vp.SetDefault(VKey.Cpm.Client.ResponseHeaderTimeout, 15*time.Second)
	vp.SetDefault(VKey.Cpm.Client.MaxIdleConns, 10)
	vp.SetDefault(VKey.Cpm.Client.MaxIdleConnsPerHost, 5)

	vp.SetDefault(VKey.Cgroup.Version, "v1")
	vp.SetDefault(VKey.Cgroup.Root, "/sys/fs/cgroup")
	vp.SetDefault(VKey.Cgroup.Hierarchy, "cpagent")
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
