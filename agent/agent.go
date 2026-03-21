package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const CONTROL_PLANE = "http://localhost:8000"
const POLL_INTERVAL = 5

func register(token string) (string, string) {

	body, _ := json.Marshal(map[string]string{
		"verification_token": token,
		"host":               "localhost",
	})

	resp, _ := http.Post(CONTROL_PLANE+"/register", "application/json", bytes.NewBuffer(body))

	var data map[string]string
	json.NewDecoder(resp.Body).Decode(&data)

	return data["agent_id"], data["user_id"]
}

func killContainer(name string, duration int) {
	exec.Command("docker", "kill", name).Run()
	time.Sleep(time.Duration(duration) * time.Second)
	exec.Command("docker", "start", name).Run()
}

func memoryStress(container string, mem int, duration int) {
	exec.Command("docker", "update", "--memory", fmt.Sprintf("%dm", mem), container).Run()
	time.Sleep(time.Duration(duration) * time.Second)
	exec.Command("docker", "update", "--memory", "0", container).Run()
}

func execute(exp map[string]interface{}) {

	id := exp["experiment_id"].(string)
	t := exp["type"].(string)

	if t == "container_kill" {
		killContainer(exp["target_container"].(string), int(exp["duration"].(float64)))
	}

	if t == "memory_stress" {
		memoryStress(
			exp["target_container"].(string),
			int(exp["memory_mb"].(float64)),
			int(exp["duration"].(float64)),
		)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"experiment_id": id,
		"status":        "completed",
	})

	http.Post(CONTROL_PLANE+"/result", "application/json", bytes.NewBuffer(body))
}

func poll(agentID string) {

	for {

		resp, err := http.Get(CONTROL_PLANE + "/poll/" + agentID)
		if err != nil {
			time.Sleep(POLL_INTERVAL * time.Second)
			continue
		}

		var exp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&exp)

		if exp["experiment_id"] != nil {
			execute(exp)
		}

		time.Sleep(POLL_INTERVAL * time.Second)
	}
}

func main() {

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter verification token: ")
	token, _ := reader.ReadString('\n')
	token = strings.TrimSpace(token)

	agentID, userID := register(token)

	fmt.Println("Agent registered:", agentID, "User:", userID)

	poll(agentID)
}
