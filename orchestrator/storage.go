package main

import (
	"encoding/json"
	"os"
	"time"
)

/* =========================
   FILE PATHS
========================= */

var mappingFile = "mapping.json"
var agentsFile = "agents.json"
var experimentsFile = "experiments.json"
var usersFile = "users.json"

/* =========================
   GENERIC JSON HELPERS
========================= */

func readJSON(file string) map[string]interface{} {

	data := make(map[string]interface{})

	f, err := os.ReadFile(file)
	if err != nil {
		return data
	}

	json.Unmarshal(f, &data)
	return data
}

func writeJSON(file string, data map[string]interface{}) {

	bytes, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(file, bytes, 0644)
}

/* =========================
   USER → AGENT MAPPING
========================= */

func storeUserAgentMapping(userID, agentID, token string) {

	data := readJSON(mappingFile)

	if _, ok := data[userID]; !ok {
		data[userID] = []interface{}{}
	}

	list := data[userID].([]interface{})

	list = append(list, map[string]interface{}{
		"agent_id":           agentID,
		"verification_token": token,
	})

	data[userID] = list

	writeJSON(mappingFile, data)
}

/* =========================
   TOKEN VERIFICATION
========================= */

func verifyToken(token string) (string, string) {

	data := readJSON(mappingFile)

	for userID, v := range data {

		list := v.([]interface{})

		for _, item := range list {

			m := item.(map[string]interface{})

			if m["verification_token"] == token {
				return userID, m["agent_id"].(string)
			}
		}
	}

	return "", ""
}

/* =========================
   AGENT STORAGE
========================= */

func registerAgentStore(agentID, host string) {

	data := readJSON(agentsFile)

	data[agentID] = map[string]interface{}{
		"host":      host,
		"last_seen": time.Now().String(),
		"status":    "active",
	}

	writeJSON(agentsFile, data)
}

func updateLastSeen(agentID string) {

	data := readJSON(agentsFile)

	if agent, ok := data[agentID]; ok {

		m := agent.(map[string]interface{})
		m["last_seen"] = time.Now().String()
		m["status"] = "active"

		data[agentID] = m
		writeJSON(agentsFile, data)
	}
}

/* =========================
   EXPERIMENT STORAGE
========================= */

func storeExperiment(id string, exp interface{}) {

	data := readJSON(experimentsFile)

	expMap := map[string]interface{}{}

	bytes, _ := json.Marshal(exp)
	json.Unmarshal(bytes, &expMap)

	expMap["status"] = "pending"
	expMap["created_at"] = time.Now().String()

	data[id] = expMap

	writeJSON(experimentsFile, data)
}

func getExperimentForAgent(agentID string) map[string]interface{} {

	data := readJSON(experimentsFile)

	for id, v := range data {

		exp := v.(map[string]interface{})

		if exp["agent_id"] == agentID && exp["status"] == "pending" {

			exp["status"] = "running"
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

	if exp, ok := data[id]; ok {

		m := exp.(map[string]interface{})
		m["status"] = status
		m["result"] = result
		m["completed_at"] = time.Now().String()

		data[id] = m
		writeJSON(experimentsFile, data)
	}
}
