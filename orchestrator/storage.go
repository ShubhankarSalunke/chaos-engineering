package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var lock sync.Mutex

var agentsFile = "agents.json"
var experimentsFile = "experiments.json"
var mappingFile = "mapping.json"

func readJSON(file string) map[string]interface{} {
	lock.Lock()
	defer lock.Unlock()

	data := make(map[string]interface{})

	bytes, err := os.ReadFile(file)
	if err != nil {
		return data
	}

	json.Unmarshal(bytes, &data)
	return data
}

func writeJSON(file string, data map[string]interface{}) {
	lock.Lock()
	defer lock.Unlock()

	bytes, _ := json.MarshalIndent(data, "", " ")
	os.WriteFile(file, bytes, 0644)
}

/* USER AGENT MAPPING */

func storeUserAgentMapping(userID, agentID, token string) {

	data := readJSON(mappingFile)

	data[userID] = map[string]interface{}{
		"agent_id":           agentID,
		"verification_token": token,
	}

	writeJSON(mappingFile, data)
}

func verifyToken(token string) (string, string) {

	data := readJSON(mappingFile)

	for user, v := range data {

		m := v.(map[string]interface{})

		if m["verification_token"] == token {
			return user, m["agent_id"].(string)
		}
	}

	return "", ""
}

/* AGENTS */

func registerAgentStore(agentID, host string) {

	data := readJSON(agentsFile)

	data[agentID] = map[string]interface{}{
		"host":      host,
		"last_seen": time.Now().UTC().String(),
	}

	writeJSON(agentsFile, data)
}

func updateLastSeen(agentID string) {

	data := readJSON(agentsFile)

	if agent, ok := data[agentID]; ok {

		m := agent.(map[string]interface{})
		m["last_seen"] = time.Now().UTC().String()
		data[agentID] = m
		writeJSON(agentsFile, data)
	}
}

/* EXPERIMENTS */

func storeExperiment(id string, exp ExperimentCreate) {

	data := readJSON(experimentsFile)

	data[id] = map[string]interface{}{
		"type":             exp.Type,
		"target_container": exp.TargetContainer,
		"duration":         exp.Duration,
		"agent_id":         exp.AgentID,

		"memory_mb":   exp.MemoryMB,
		"cpu_percent": exp.CPUPercent,
		"latency_ms":  exp.LatencyMS,

		"status":      "pending",
		"assigned_to": exp.AgentID,
	}

	writeJSON(experimentsFile, data)
}

func getExperimentForAgent(agentID string) map[string]interface{} {

	data := readJSON(experimentsFile)

	for id, v := range data {

		exp := v.(map[string]interface{})

		if exp["status"] == "pending" && exp["assigned_to"] == agentID {

			exp["status"] = "assigned"
			data[id] = exp
			writeJSON(experimentsFile, data)

			exp["experiment_id"] = id
			return exp
		}
	}

	return nil
}

func updateExperimentStatus(id, status string, result map[string]interface{}) {

	data := readJSON(experimentsFile)

	exp := data[id].(map[string]interface{})
	exp["status"] = status

	if result != nil {
		exp["result"] = result
	}

	data[id] = exp
	writeJSON(experimentsFile, data)
}

/* APIs */

func getAgents(c *gin.Context) {
	c.JSON(200, readJSON(agentsFile))
}

func getExperiments(c *gin.Context) {
	c.JSON(200, readJSON(experimentsFile))
}
