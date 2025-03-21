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
}{}

func SetDefaults(vp *viper.Viper) {
	vp.SetDefault(VKey.Listen.Http.Port, 9900)
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
