package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/ShubhankarSalunke/chaos-engineering.git/cli/config"
	"github.com/spf13/cobra"
)

var createExperimentCmd = &cobra.Command{
	Use:   "create-experiment",
	Short: "Create experiment",
	Run: func(cmd *cobra.Command, args []string) {

		server := config.GetServerURL()
		reader := bufio.NewReader(os.Stdin)

		// Agent ID
		fmt.Print("Enter Agent ID: ")
		agentID, _ := reader.ReadString('\n')
		agentID = strings.TrimSpace(agentID)

		// Experiment Type
		fmt.Print("Enter Type (container_kill / cpu_stress / memory_stress / network_latency): ")
		expType, _ := reader.ReadString('\n')
		expType = strings.TrimSpace(expType)

		fmt.Print("Enter Duration (seconds): ")
		durationStr, _ := reader.ReadString('\n')
		durationStr = strings.TrimSpace(durationStr)

		duration, err := strconv.Atoi(durationStr)
		if err != nil || duration <= 0 {
			fmt.Println("Invalid duration")
			return
		}

		if agentID == "" || expType == "" {
			fmt.Println("Agent ID and Type cannot be empty")
			return
		}

		payload := map[string]interface{}{
			"agent_id": agentID,
			"type":     expType,
			"duration": duration,
		}

		switch expType {

		case "container_kill":
			fmt.Print("Enter Container Name/ID: ")
			val, _ := reader.ReadString('\n')
			val = strings.TrimSpace(val)

			if val == "" {
				fmt.Println("Container cannot be empty")
				return
			}

			payload["target_container"] = val

		case "cpu_stress":
			fmt.Print("Enter CPU % (1-100): ")
			val, _ := reader.ReadString('\n')
			val = strings.TrimSpace(val)

			cpu, err := strconv.Atoi(val)
			if err != nil || cpu <= 0 || cpu > 100 {
				fmt.Println("Invalid CPU percent")
				return
			}
			payload["cpu_percent"] = cpu

		case "memory_stress":
			fmt.Print("Enter Memory (MB): ")
			val, _ := reader.ReadString('\n')
			val = strings.TrimSpace(val)

			mem, err := strconv.Atoi(val)
			if err != nil || mem <= 0 {
				fmt.Println("Invalid memory value")
				return
			}
			payload["memory_mb"] = mem

		case "network_latency":
			fmt.Print("Enter Latency (ms): ")
			val, _ := reader.ReadString('\n')
			val = strings.TrimSpace(val)

			lat, err := strconv.Atoi(val)
			if err != nil || lat <= 0 {
				fmt.Println("Invalid latency")
				return
			}
			payload["latency_ms"] = lat

		default:
			fmt.Println("Invalid experiment type")
			return
		}

		body, err := json.Marshal(payload)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		resp, err := http.Post(server+"/create-experiment",
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

		fmt.Println("\n✅ Experiment Created")
		fmt.Println("Experiment ID:", result["experiment_id"])
	},
}

func init() {
	rootCmd.AddCommand(createExperimentCmd)
}
