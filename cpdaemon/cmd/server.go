package cmd

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/Netis/cloud-probe/cpdaemon/cmd/internal/asm"
)

func init() {
	rootCmd.AddCommand(serverCmd)
}

var serverCmd = &cobra.Command{
	Use: "server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		vp, err := getViper()
		if err != nil {
			return err
		}

		return runSvr(cmd.Context(), vp, nil)
	},
}

func runSvr(
	ctx context.Context,
	vp *viper.Viper,
	done func(*asm.Instance),
) error {
	ins := &asm.Instance{
		Sg: make(asm.Singleton),
		Vp: vp,
	}

	{
		_, cleanup, err := asm.InitServer(ctx, ins)
		if err != nil {
			return err
		}
		defer cleanup()
	}

	if mux := ins.Sg.Mux(); mux != nil {
		err := ins.ListenHTTP(vp, mux)
		if err != nil {
			return err
		}
	}

	group, ctx := errgroup.WithContext(ctx)
	for _, fn := range ins.Daemons {
		fn := fn
		group.Go(func() error {
			return fn(ctx)
		})
	}

	if done != nil {
		done(ins) // for test
	}

	ch := make(chan error, 1)
	go func() {
		ch <- group.Wait()
	}()

	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		select {
		case err := <-ch:
			return err
		case <-time.After(time.Minute):
			return errors.New("force exit after 60s")
		}
	}
}
