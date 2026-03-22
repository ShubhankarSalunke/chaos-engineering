package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "chaos",
	Short: "Chaos Engineering CLI",
}

func Execute() {
	rootCmd.Execute()
}
