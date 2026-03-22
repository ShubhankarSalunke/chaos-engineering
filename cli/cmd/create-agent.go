package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/ShubhankarSalunke/chaos-engineering.git/cli/config"
	"github.com/spf13/cobra"
)

var createAgentCmd = &cobra.Command{
	Use:   "create-agent",
	Short: "Create agent",
	Run: func(cmd *cobra.Command, args []string) {

		server := config.GetServerURL()
		reader := bufio.NewReader(os.Stdin)

		// Input: User ID
		fmt.Print("Enter User ID: ")
		userID, _ := reader.ReadString('\n')
		userID = strings.TrimSpace(userID)

		// Input: Agent ID
		fmt.Print("Enter Agent ID: ")
		agentID, _ := reader.ReadString('\n')
		agentID = strings.TrimSpace(agentID)

		// Basic validation
		if userID == "" || agentID == "" {
			fmt.Println("User ID and Agent ID cannot be empty")
			return
		}

		payload := map[string]string{
			"user_id":  userID,
			"agent_id": agentID,
		}

		body, err := json.Marshal(payload)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		resp, err := http.Post(server+"/create-agent",
			"application/json",
			bytes.NewBuffer(body))

		if err != nil {
			fmt.Println("Request failed:", err)
			return
		}
		defer resp.Body.Close()

		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fmt.Println("Error decoding response:", err)
			return
		}

		fmt.Println("\n✅ Agent Created Successfully")
		fmt.Println("Agent ID:", result["agent_id"])
		fmt.Println("Verification Token:", result["verification_token"])
	},
}

func init() {
	rootCmd.AddCommand(createAgentCmd)
}