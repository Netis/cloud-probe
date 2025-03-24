package asm

import (
	"os"
	"path/filepath"
	"reflect"

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
		TasksFile string
	}
}{}

func SetDefaults(vp *viper.Viper) {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	vp.SetDefault(VKey.Listen.Http.Port, 9022)
	vp.SetDefault(VKey.Cpm.Reg.UuidFile, "/usr/local/bin/uuid")
	vp.SetDefault(VKey.Cpm.TasksFile, filepath.Join(cwd, "cpm-tasks.json"))
	vp.SetDefault(VKey.Agent.Executable, "cpagent")
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
