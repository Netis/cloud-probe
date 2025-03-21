package asm

import (
	"context"
	"reflect"

	"github.com/spf13/viper"
)

type Daemon func(ctx context.Context) error

type Instance struct {
	Sg      Singleton
	Vp      *viper.Viper
	Daemons []Daemon
}

type Singleton map[reflect.Type]any

func Build1[T any](sg Singleton, fn func() T) T {
	key := reflect.TypeOf(new(T))
	r, ok := sg[key]
	if ok {
		return r.(T)
	}

	res := fn()
	sg[key] = res
	return res
}

func Build2[T any](sg Singleton, fn func() (T, error)) (T, error) {
	key := reflect.TypeOf(new(T))
	r, ok := sg[key]
	if ok {
		return r.(T), nil
	}

	var z T
	res, err := fn()
	if err != nil {
		return z, err
	}
	sg[key] = res
	return res, nil
}

func Build3[T any](sg Singleton, fn func() (T, func(), error)) (T, func(), error) {
	key := reflect.TypeOf(new(T))
	r, ok := sg[key]
	if ok {
		return r.(T), func() {}, nil
	}

	var z T
	res, cleanup, err := fn()
	if err != nil {
		return z, nil, err
	}
	sg[key] = res
	return res, cleanup, nil
}
