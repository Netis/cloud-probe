//go:build wireinject

package asm

import (
	"context"

	"github.com/google/wire"
)

func InitServer(
	ctx context.Context,
	ins *Instance,
) (ServerEps, func(), error) {
	panic(wire.Build(
		wire.FieldsOf(new(*Instance), "Vp"),
		NewCpmClient,
		NewCpmSyncer,
		GetMux,
		NewServerEps,
	))
}
