package asm

import (
	"os"
	"path/filepath"
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
		TasksFile           string
		AgentSockFile       string
		AllowUnknownStartup string
	}
}{}

func SetDefaults(vp *viper.Viper) {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	vp.SetDefault(VKey.Listen.Http.Port, 9022)
	vp.SetDefault(VKey.Cpm.Reg.UuidFile, "/usr/local/bin/uuid")
	vp.SetDefault(VKey.Cpm.TasksFile, filepath.Join(cwd, "cpm-agent-tasks.json"))
	vp.SetDefault(VKey.Cpm.AgentSockFile, filepath.Join(cwd, "cpm-agent.sock"))
	vp.SetDefault(VKey.Agent.Executable, "cpagent")

	vp.SetDefault(VKey.Cpm.Client.Timeout, 15*time.Second)
	vp.SetDefault(VKey.Cpm.Client.DialTimeout, 5*time.Second)
	vp.SetDefault(VKey.Cpm.Client.ResponseHeaderTimeout, 15*time.Second)
	vp.SetDefault(VKey.Cpm.Client.MaxIdleConns, 10)
	vp.SetDefault(VKey.Cpm.Client.MaxIdleConnsPerHost, 5)

	vp.SetDefault(VKey.Cpm.AllowUnknownStartup, false)
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
