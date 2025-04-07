package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var Version string = "0.0.0"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use: "version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("version: %s\n\n", Version)

		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		info.Deps = nil
		fmt.Print(info.String())
	},
}
