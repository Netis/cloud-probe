package cmd

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"gopkg.in/natefinch/lumberjack.v2"

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

		if err := initServerLogger(vp); err != nil {
			return err
		}

		return runSvr(cmd.Context(), vp, nil)
	},
}

func initServerLogger(vp *viper.Viper) error {
	var w io.Writer
	switch v := vp.GetString(asm.VKey.Log.Output.Type); v {
	case "stdout":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	case "rotating_file":
		fileName := vp.GetString(asm.VKey.Log.Output.RotatingFile.FileName)
		if fileName == "" {
			return errors.New("log.output.rotating_file.file_name is empty")
		}
		w = &lumberjack.Logger{
			Filename:   fileName,
			MaxSize:    vp.GetInt(asm.VKey.Log.Output.RotatingFile.MaxSize),
			MaxBackups: vp.GetInt(asm.VKey.Log.Output.RotatingFile.MaxBackups),
			MaxAge:     vp.GetInt(asm.VKey.Log.Output.RotatingFile.MaxAge),
		}
	default:
		return errors.Errorf("invalid log.output.type: %s", v)
	}

	var level slog.Leveler
	switch strings.ToLower(vp.GetString(asm.VKey.Log.Level)) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	hd := slog.NewTextHandler(w, &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	})
	lg := slog.New(hd)
	slog.SetDefault(lg)
	return nil
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
