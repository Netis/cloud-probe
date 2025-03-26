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
			Address string
			Port    string
		}
	}
	Agent struct {
		Executable string
	}
	Kvm struct {
		ListNameScript      string
		ListInterfaceScript string
	}
	Container struct {
		GetHostPidScript string
	}
	Cgroup struct {
		Version   string
		Root      string
		Hierarchy string
	}
	Cpm struct {
		BaseUrl string
		Client  struct {
			Timeout               string
			DialTimeout           string
			ResponseHeaderTimeout string
			MaxIdleConns          string
			MaxIdleConnsPerHost   string
			Pkcs12CertFile        string
			Pkcs12CertPassword    string
		}
		Reg struct {
			Name          string
			UuidFile      string
			PlatformId    string
			DeployEnv     string
			Labels        string
			IncludingNICs string

			PodName   string
			Namespace string
			NodeName  string
		}
		Agent struct {
			TasksFile string
			SockFile  string
		}
	}
}{}

func SetDefaults(vp *viper.Viper) {
	vp.SetDefault(VKey.Listen.Http.Port, 9022)

	// 兼容旧的C++版本
	vp.SetDefault(VKey.Cpm.Reg.UuidFile, "/usr/local/bin/uuid")

	vp.SetDefault(VKey.Cpm.Agent.TasksFile, "cpm-tasks.json")
	vp.SetDefault(VKey.Cpm.Agent.SockFile, "cpm-agent.sock")
	vp.SetDefault(VKey.Agent.Executable, "cpagent")

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
			fv.SetString(prefix + ft.Name)
		case reflect.Struct:
			fillKey(fv.Addr(), prefix+ft.Name+".")
		}
	}
}
