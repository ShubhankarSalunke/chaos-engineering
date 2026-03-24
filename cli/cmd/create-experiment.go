package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ShubhankarSalunke/chaos-engineering.git/cli/config"
	"github.com/spf13/cobra"
)

var (
	expType    string
	agentIDExp string
	duration   int
	cpu        int
	memory     int
	latency    int
	target     string
)

var createExperimentCmd = &cobra.Command{
	Use:   "create-experiment",
	Short: "Create experiment",
	Run: func(cmd *cobra.Command, args []string) {

		if expType == "" || agentIDExp == "" || duration <= 0 {
			fmt.Println("type, agent and duration are required")
			return
		}

		payload := map[string]interface{}{
			"type":             expType,
			"agent_id":         agentIDExp,
			"duration":         duration,
			"target_container": target,
		}

		switch expType {

		case "cpu_stress":
			if cpu <= 0 || cpu > 100 {
				fmt.Println("cpu must be between 1-100")
				return
			}
			payload["cpu_percent"] = cpu

		case "memory_stress":
			if memory <= 0 {
				fmt.Println("memory must be > 0")
				return
			}
			payload["memory_mb"] = memory

		case "network_latency":
			if latency <= 0 {
				fmt.Println("latency must be > 0")
				return
			}
			payload["latency_ms"] = latency

		case "container_kill":
			if target == "" {
				fmt.Println("target container required")
				return
			}

		default:
			fmt.Println("invalid experiment type")
			return
		}

		body, err := json.Marshal(payload)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		resp, err := doRequest("POST", config.GetServerURL()+"/create-experiment", body)
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

		fmt.Println("\n✅ Experiment Created")
		fmt.Println("Experiment ID:", result["experiment_id"])
	},
}

func init() {
	createExperimentCmd.Flags().StringVar(&expType, "type", "", "Experiment type")
	createExperimentCmd.Flags().StringVar(&agentIDExp, "agent", "", "Agent ID")
	createExperimentCmd.Flags().IntVar(&duration, "duration", 30, "Duration in seconds")
	createExperimentCmd.Flags().IntVar(&cpu, "cpu", 0, "CPU %")
	createExperimentCmd.Flags().IntVar(&memory, "memory", 0, "Memory MB")
	createExperimentCmd.Flags().IntVar(&latency, "latency", 0, "Latency ms")
	createExperimentCmd.Flags().StringVar(&target, "target", "", "Target container")

	createExperimentCmd.MarkFlagRequired("type")
	createExperimentCmd.MarkFlagRequired("agent")

	rootCmd.AddCommand(createExperimentCmd)
}
