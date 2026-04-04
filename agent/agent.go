package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const CONTROL_PLANE = "http://localhost:8001"
const POLL_INTERVAL = 5
const CMD_TIMEOUT = 10 * time.Second

var agentLatencyMs int = 0
var packetLoss float64 = 0.0

func runCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), CMD_TIMEOUT)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("command timed out: %s %v", name, args)
	}

	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, string(out))
	}

	return out, nil
}

func containerExists(name string) bool {
	_, err := runCommand("docker", "inspect", name)
	return err == nil
}

func register(token string) (string, string, error) {

	body, _ := json.Marshal(map[string]string{
		"verification_token": token,
		"host":               "localhost",
	})

	resp, err := http.Post(CONTROL_PLANE+"/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", err
	}

	return data["agent_id"], data["user_id"], nil
}
func getMemory(container string) (int64, error) {
	out, err := runCommand("docker", "inspect", "--format", "{{.HostConfig.Memory}}", container)
	if err != nil {
		return 0, err
	}

	val := strings.TrimSpace(string(out))

	memBytes, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, err
	}

	return memBytes, nil
}

func setMemory(container string, bytes int64) error {
	_, err := runCommand("docker", "update", "--memory", fmt.Sprintf("%d", bytes), container)
	return err
}

func memoryStress(container string, memMB int, duration int) {

	fmt.Println("Starting memory stress on:", container)

	if !containerExists(container) {
		fmt.Println("Container does not exist:", container)
		return
	}

	originalMem, err := getMemory(container)
	if err != nil {
		fmt.Println("Failed to fetch original memory:", err)
		return
	}

	fmt.Println("Original memory (MB):", originalMem/(1024*1024))

	_, err = runCommand("docker", "update", "--memory", fmt.Sprintf("%dm", memMB), container)
	if err != nil {
		fmt.Println("Failed to apply memory stress:", err)
		return
	}

	time.Sleep(time.Duration(duration) * time.Second)

	for i := 0; i < 3; i++ {
		err = setMemory(container, originalMem)
		if err == nil {
			fmt.Println("Memory restored")
			return
		}
		time.Sleep(2 * time.Second)
	}

	fmt.Println("Failed to restore memory")
}

func killContainer(name string, duration int) {

	fmt.Println("Killing container:", name)

	if !containerExists(name) {
		fmt.Println("Container does not exist:", name)
		return
	}

	_, err := runCommand("docker", "kill", name)
	if err != nil {
		fmt.Println("Kill failed:", err)
		return
	}

	time.Sleep(time.Duration(duration) * time.Second)

	_, err = runCommand("docker", "start", name)
	if err != nil {
		fmt.Println("Restart failed:", err)
		return
	}

	fmt.Println("Container restarted")
}

func cpuStressInstance(cores int, duration int) {

	fmt.Println("Starting CPU stress")

	if cores <= 0 {
		cores = 1
	}

	stop := make(chan bool)

	for i := 0; i < cores; i++ {
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = 1 + 1
				}
			}
		}()
	}

	time.Sleep(time.Duration(duration) * time.Second)
	close(stop)

	fmt.Println("CPU stress completed")
}

func memoryStressInstance(memMB int, duration int) {

	fmt.Println("Starting INSTANCE memory stress")

	size := memMB * 1024 * 1024
	data := make([]byte, size)

	for i := 0; i < len(data); i += 4096 {
		data[i] = byte(i % 256)
	}

	time.Sleep(time.Duration(duration) * time.Second)

	data = nil

	fmt.Println("Memory stress completed")
}

func applyNetworkChaos() bool {

	if packetLoss > 0 {
		if rand.Float64() < packetLoss {
			fmt.Println("Simulating packet drop")
			return false
		}
	}

	if agentLatencyMs > 0 {
		time.Sleep(time.Duration(agentLatencyMs) * time.Millisecond)
	}

	return true
}

func execute(exp map[string]interface{}) {

	id, _ := exp["experiment_id"].(string)
	t, _ := exp["type"].(string)

	fmt.Println("Executing:", id, "Type:", t)

	switch t {

	case "container_kill":
		killContainer(
			exp["target_container"].(string),
			int(exp["duration"].(float64)),
		)

	case "memory_stress":
		memoryStress(
			exp["target_container"].(string),
			int(exp["memory_mb"].(float64)),
			int(exp["duration"].(float64)),
		)

	case "cpu_stress_instance":
		cpuStressInstance(
			int(exp["cpu_cores"].(float64)),
			int(exp["duration"].(float64)),
		)

	case "memory_stress_instance":
		memoryStressInstance(
			int(exp["memory_mb"].(float64)),
			int(exp["duration"].(float64)),
		)

	case "network_latency_instance":
		agentLatencyMs = int(exp["latency_ms"].(float64))
		fmt.Println("Set agent latency:", agentLatencyMs)

	case "packet_loss":
		packetLoss = exp["loss"].(float64)
		fmt.Println("Set packet loss:", packetLoss)

	default:
		fmt.Println("Unknown experiment:", t)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"experiment_id": id,
		"status":        "completed",
	})

	http.Post(CONTROL_PLANE+"/result", "application/json", bytes.NewBuffer(body))
}

func poll(agentID string) {

	for {

		if !applyNetworkChaos() {
			time.Sleep(POLL_INTERVAL * time.Second)
			continue
		}

		resp, err := http.Get(CONTROL_PLANE + "/poll/" + agentID)
		if err != nil {
			fmt.Println("Polling error:", err)
			time.Sleep(POLL_INTERVAL * time.Second)
			continue
		}

		var exp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&exp)
		resp.Body.Close()

		if err != nil {
			fmt.Println("Invalid response:", err)
			time.Sleep(POLL_INTERVAL * time.Second)
			continue
		}

		if exp["experiment_id"] != nil {
			execute(exp)
		}

		time.Sleep(POLL_INTERVAL * time.Second)
	}
}

func main() {

	rand.Seed(time.Now().UnixNano())

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter verification token: ")
	token, _ := reader.ReadString('\n')
	token = strings.TrimSpace(token)

	agentID, userID, err := register(token)
	if err != nil {
		fmt.Println("Registration failed:", err)
		return
	}

	fmt.Println("Agent registered:", agentID, "User:", userID)

	poll(agentID)
}
