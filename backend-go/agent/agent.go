package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"
)

const CONTROL_PLANE = "http://localhost:8000"
const POLL_INTERVAL = 5

type Experiment struct {
	ExperimentID    string `json:"experiment_id"`
	Type            string `json:"type"`
	TargetContainer string `json:"target_container"`
	Duration        int    `json:"duration"`
	MemoryMB        int    `json:"memory_mb"`
}

func killContainer(container string, duration int) {

	exec.Command("docker", "kill", container).Run()

	fmt.Println("container killed")

	time.Sleep(time.Duration(duration) * time.Second)

	exec.Command("docker", "start", container).Run()

	fmt.Println("container restarted")
}

func memoryStress(container string, memory int, duration int) {

	exec.Command("docker", "update",
		"--memory", fmt.Sprintf("%dm", memory),
		container).Run()

	time.Sleep(time.Duration(duration) * time.Second)

	exec.Command("docker", "update",
		"--memory", "0",
		container).Run()
}

func executeExperiment(exp Experiment) {

	if exp.Type == "container_kill" {
		killContainer(exp.TargetContainer, exp.Duration)
	}

	if exp.Type == "memory_stress" {
		memoryStress(exp.TargetContainer, exp.MemoryMB, exp.Duration)
	}

	result := map[string]interface{}{
		"experiment_id": exp.ExperimentID,
		"status":        "completed",
	}

	body, _ := json.Marshal(result)

	http.Post(
		CONTROL_PLANE+"/result",
		"application/json",
		bytes.NewBuffer(body),
	)
}

func poll(agentID string) {

	for {

		resp, err := http.Get(CONTROL_PLANE + "/poll/" + agentID)

		if err != nil {
			time.Sleep(POLL_INTERVAL * time.Second)
			continue
		}

		var exp Experiment

		json.NewDecoder(resp.Body).Decode(&exp)

		if exp.ExperimentID != "" {
			executeExperiment(exp)
		}

		time.Sleep(POLL_INTERVAL * time.Second)
	}
}

func main() {

	agentID := "agent-1"

	fmt.Println("agent started")

	poll(agentID)
}
