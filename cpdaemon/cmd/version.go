package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/Netis/cloud-probe/cpdaemon/pkg/version"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use: "version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("version: %s\n\n", version.Version)

		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		info.Deps = nil
		fmt.Print(info.String())
	},
}
