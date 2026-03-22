package main

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type UserAgentMapping struct {
	UserID  string `json:"user_id"`
	AgentID string `json:"agent_id"`
}

type AgentRegister struct {
	VerificationToken string `json:"verification_token"`
	Host              string `json:"host"`
}

type ExperimentCreate struct {
	Type            string `json:"type"`
	TargetContainer string `json:"target_container"`
	Duration        int    `json:"duration"`
	AgentID         string `json:"agent_id"`

	MemoryMB   int `json:"memory_mb,omitempty"`
	CPUPercent int `json:"cpu_percent,omitempty"`
	LatencyMS  int `json:"latency_ms,omitempty"`
}

type ExperimentResult struct {
	ExperimentID string                 `json:"experiment_id"`
	Status       string                 `json:"status"`
	Result       map[string]interface{} `json:"result"`
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func main() {

	r := gin.Default()
	r.Use(cors.Default())

	r.POST("/create-agent", createAgent)
	r.POST("/register", registerAgent)
	r.GET("/poll/:agent_id", pollAgent)
	r.POST("/result", submitResult)
	r.POST("/create-experiment", createExperiment)
	r.GET("/agents", getAgents)
	r.GET("/experiments", getExperiments)

	r.Run(":8000")
}

func createAgent(c *gin.Context) {

	var req UserAgentMapping
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	token := uuid.New().String()

	storeUserAgentMapping(req.UserID, req.AgentID, hashToken(token))

	c.JSON(200, gin.H{
		"agent_id":           req.AgentID,
		"verification_token": token,
	})
}

func registerAgent(c *gin.Context) {

	var req AgentRegister
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	userID, agentID := verifyToken(hashToken(req.VerificationToken))

	if userID == "" {
		c.JSON(401, gin.H{"error": "invalid token"})
		return
	}

	registerAgentStore(agentID, req.Host)

	c.JSON(200, gin.H{
		"agent_id": agentID,
		"user_id":  userID,
	})
}

func pollAgent(c *gin.Context) {

	agentID := c.Param("agent_id")

	updateLastSeen(agentID)

	exp := getExperimentForAgent(agentID)

	if exp == nil {
		c.JSON(200, gin.H{})
		return
	}

	c.JSON(200, exp)
}

func submitResult(c *gin.Context) {

	var result ExperimentResult
	if err := c.BindJSON(&result); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	updateExperimentStatus(result.ExperimentID, result.Status, result.Result)

	c.JSON(200, gin.H{"message": "result recorded"})
}

func createExperiment(c *gin.Context) {

	var exp ExperimentCreate
	if err := c.BindJSON(&exp); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if exp.Type == "" || exp.AgentID == "" || exp.Duration <= 0 {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	switch exp.Type {
	case "memory_stress":
		if exp.MemoryMB <= 0 {
			c.JSON(400, gin.H{"error": "memory_mb required"})
			return
		}

	case "cpu_stress":
		if exp.CPUPercent <= 0 || exp.CPUPercent > 100 {
			c.JSON(400, gin.H{"error": "cpu_percent must be 1-100"})
			return
		}

	case "network_latency":
		if exp.LatencyMS <= 0 {
			c.JSON(400, gin.H{"error": "latency_ms required"})
			return
		}
	}

	id := uuid.New().String()

	storeExperiment(id, exp)

	c.JSON(200, gin.H{"experiment_id": id})
}
