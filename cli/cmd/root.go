package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "lucifer",
	Short: "Chaos Engineering CLI",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// func init() {
// 	rootCmd.AddCommand(createAgentCmd)
// 	rootCmd.AddCommand(createExperimentCmd)
// }
