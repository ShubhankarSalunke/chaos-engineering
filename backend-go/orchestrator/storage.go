package main

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/gin-gonic/gin"
)

var (
	experimentsFile = "experiments.json"
	mutex           sync.Mutex
)

type Experiment struct {
	ID              string `json:"experiment_id"`
	Type            string `json:"type"`
	TargetContainer string `json:"target_container"`
	Duration        int    `json:"duration"`
	AgentID         string `json:"agent_id"`
	Status          string `json:"status"`
}

func readExperiments() map[string]Experiment {

	mutex.Lock()
	defer mutex.Unlock()

	file, err := os.ReadFile(experimentsFile)

	if err != nil {
		return make(map[string]Experiment)
	}

	var data map[string]Experiment

	json.Unmarshal(file, &data)

	if data == nil {
		data = make(map[string]Experiment)
	}

	return data
}

func writeExperiments(data map[string]Experiment) {

	mutex.Lock()
	defer mutex.Unlock()

	bytes, _ := json.MarshalIndent(data, "", " ")

	os.WriteFile(experimentsFile, bytes, 0644)
}

func storeExperiment(id string, exp ExperimentCreate) {

	data := readExperiments()

	data[id] = Experiment{
		ID:              id,
		Type:            exp.Type,
		TargetContainer: exp.TargetContainer,
		Duration:        exp.Duration,
		AgentID:         exp.AgentID,
		Status:          "pending",
	}

	writeExperiments(data)
}

func getExperimentForAgent(agentID string) *Experiment {

	data := readExperiments()

	for id, exp := range data {

		if exp.Status == "pending" && exp.AgentID == agentID {

			exp.Status = "assigned"
			data[id] = exp
			writeExperiments(data)

			return &exp
		}
	}

	return nil
}

func updateExperiment(result ExperimentResult) {

	data := readExperiments()

	exp := data[result.ExperimentID]

	exp.Status = result.Status

	data[result.ExperimentID] = exp

	writeExperiments(data)
}

func getExperiments(c *gin.Context) {

	data := readExperiments()

	c.JSON(200, data)
}

func getAgents(c *gin.Context) {

	c.JSON(200, gin.H{
		"agents": "agent tracking can be added later",
	})
}
