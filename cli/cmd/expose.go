package cmd

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

var exposeCmd = &cobra.Command{
	Use:   "expose",
	Short: "Expose control plane",
	Run: func(cmd *cobra.Command, args []string) {

		fmt.Println("Starting tunnel on port 8000...")

		command := exec.Command("ngrok", "http", "8000")
		command.Stdout = cmd.OutOrStdout()
		command.Stderr = cmd.ErrOrStderr()

		if err := command.Run(); err != nil {
			fmt.Println("Error:", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(exposeCmd)
}
