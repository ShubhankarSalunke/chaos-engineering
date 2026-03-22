package cmd

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start control plane",
	Run: func(cmd *cobra.Command, args []string) {

		fmt.Println("Starting control plane at http://localhost:8000")

		command := exec.Command("go", "run", "../orchestrator/main.go", "../orchestrator/storage.go")
		command.Stdout = cmd.OutOrStdout()
		command.Stderr = cmd.ErrOrStderr()

		if err := command.Run(); err != nil {
			fmt.Println("Error:", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
