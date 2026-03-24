package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ShubhankarSalunke/chaos-engineering.git/cli/config"
	"github.com/spf13/cobra"
)

var agentID string

var createAgentCmd = &cobra.Command{
	Use:   "create-agent",
	Short: "Create agent",
	Run: func(cmd *cobra.Command, args []string) {

		if agentID == "" {
			fmt.Println("Agent ID is required")
			return
		}

		payload := map[string]string{
			"agent_id": agentID,
		}

		body, err := json.Marshal(payload)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		resp, err := doRequest("POST", config.GetServerURL()+"/create-agent", body)
		if err != nil {
			fmt.Println("Request failed:", err)
			return
		}
		defer resp.Body.Close()

		resBody, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != 200 {
			fmt.Println("Error:", string(resBody))
			return
		}

		var result map[string]interface{}
		json.Unmarshal(resBody, &result)

		fmt.Println("\n✅ Agent Created Successfully")
		fmt.Println("Agent ID:", result["agent_id"])
		fmt.Println("Verification Token:", result["verification_token"])
	},
}

func init() {
	createAgentCmd.Flags().StringVar(&agentID, "id", "", "Agent ID")
	createAgentCmd.MarkFlagRequired("id")

	rootCmd.AddCommand(createAgentCmd)
}
