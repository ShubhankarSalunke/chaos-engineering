package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ExperimentCreate struct {
	Type            string `json:"type"`
	TargetContainer string `json:"target_container"`
	Duration        int    `json:"duration"`
	AgentID         string `json:"agent_id"`
	MemoryMB        int    `json:"memory_mb,omitempty"`
}

type ExperimentResult struct {
	ExperimentID string                 `json:"experiment_id"`
	Status       string                 `json:"status"`
	Result       map[string]interface{} `json:"result"`
}

func main() {

	r := gin.Default()

	r.POST("/create-experiment", createExperiment)
	r.GET("/poll/:agent_id", pollAgent)
	r.POST("/result", submitResult)

	r.GET("/agents", getAgents)
	r.GET("/experiments", getExperiments)

	r.Run(":8000")
}

func createExperiment(c *gin.Context) {

	var exp ExperimentCreate

	if err := c.BindJSON(&exp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	expID := uuid.New().String()

	storeExperiment(expID, exp)

	c.JSON(http.StatusOK, gin.H{
		"experiment_id": expID,
	})
}

func pollAgent(c *gin.Context) {

	agentID := c.Param("agent_id")

	exp := getExperimentForAgent(agentID)

	if exp == nil {
		c.JSON(http.StatusOK, gin.H{})
		return
	}

	c.JSON(http.StatusOK, exp)
}

func submitResult(c *gin.Context) {

	var result ExperimentResult

	if err := c.BindJSON(&result); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updateExperiment(result)

	c.JSON(http.StatusOK, gin.H{
		"message": "result recorded",
	})
}
