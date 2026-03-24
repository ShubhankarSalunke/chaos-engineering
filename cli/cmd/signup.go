package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ShubhankarSalunke/chaos-engineering.git/cli/config"
	"github.com/spf13/cobra"
)

var signupCmd = &cobra.Command{
	Use:   "signup",
	Short: "Create a new user and store API token",
	Run: func(cmd *cobra.Command, args []string) {

		resp, err := doRequest("POST", config.GetServerURL()+"/create-user", nil)
		if err != nil {
			fmt.Println("Request failed:", err)
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != 200 {
			fmt.Println("Error:", string(body))
			return
		}

		var result map[string]interface{}
		json.Unmarshal(body, &result)

		token := result["token"].(string)

		cfg := config.Config{
			Token:     token,
			ServerURL: config.GetServerURL(),
		}

		err = config.SaveConfig(cfg)
		if err != nil {
			fmt.Println("Failed to save config:", err)
			return
		}

		fmt.Println("✅ Signup successful")
		fmt.Println("Token saved to ~/.chaos/config.json")
	},
}

func init() {
	rootCmd.AddCommand(signupCmd)
}
