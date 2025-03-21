package asm

import (
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
		RegConfig struct {
			Name          string
			UuidFile      string
			IncludingNICs string
			PodName       string
			Namespace     string
			PlatformId    string
			Labels        string
			DeployEnv     string
		}
	}
}{}

func SetDefaults(vp *viper.Viper) {
	vp.SetDefault(VKey.Listen.Http.Port, 9022)
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
