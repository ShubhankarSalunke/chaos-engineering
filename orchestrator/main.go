package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/* =========================
   STRUCTS
========================= */

type UserAgentMapping struct {
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

type UserCreate struct {
	UserID string `json:"user_id"`
}

/* =========================
   UTILS
========================= */

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

/* =========================
   MAIN
========================= */

func main() {

	r := gin.Default()
	r.Use(cors.Default())

	// PUBLIC ROUTES
	r.POST("/create-user", createUser)
	r.POST("/register", registerAgent)
	r.GET("/poll/:agent_id", pollAgent)
	r.POST("/result", submitResult)

	// AUTH ROUTES
	auth := r.Group("/")
	auth.Use(authMiddleware())

	auth.POST("/create-agent", createAgent)
	auth.POST("/create-experiment", createExperiment)
	auth.GET("/agents", getAgents)
	auth.GET("/experiments", getExperiments)

	r.Run("0.0.0.0:8001")
}

/* =========================
   AUTH
========================= */

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		token := c.GetHeader("Authorization")

		if token == "" {
			c.JSON(401, gin.H{"error": "missing token"})
			c.Abort()
			return
		}

		token = strings.TrimPrefix(token, "Bearer ")
		hashed := hashToken(token)

		data := readJSON("users.json")

		for userID, v := range data {
			m := v.(map[string]interface{})

			if m["token"] == hashed {
				c.Set("user_id", userID)
				c.Next()
				return
			}
		}

		c.JSON(401, gin.H{"error": "invalid token"})
		c.Abort()
	}
}

func createUser(c *gin.Context) {

	var req UserCreate
	c.ShouldBindJSON(&req)

	userID := req.UserID
	if userID == "" {
		userID = uuid.New().String()
	}

	data := readJSON("users.json")

	if _, exists := data[userID]; exists {
		c.JSON(400, gin.H{"error": "user_id already exists"})
		return
	}

	rawToken := uuid.New().String()

	data[userID] = map[string]interface{}{
		"token": hashToken(rawToken),
	}

	writeJSON("users.json", data)

	c.JSON(200, gin.H{
		"user_id": userID,
		"token":   rawToken,
	})
}

/* =========================
   AGENT APIs
========================= */

func createAgent(c *gin.Context) {

	var req UserAgentMapping
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetString("user_id")

	token := uuid.New().String()

	storeUserAgentMapping(userID, req.AgentID, hashToken(token))

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

/* =========================
   EXPERIMENT APIs
========================= */

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

/* =========================
   QUERY APIs (USER SCOPED)
========================= */

func getAgents(c *gin.Context) {

	userID := c.GetString("user_id")

	mapping := readJSON(mappingFile)
	agents := readJSON(agentsFile)

	result := make(map[string]interface{})

	if v, ok := mapping[userID]; ok {

		list := v.([]interface{})

		for _, item := range list {

			m := item.(map[string]interface{})
			agentID := m["agent_id"].(string)

			if agent, exists := agents[agentID]; exists {
				result[agentID] = agent
			}
		}
	}

	c.JSON(200, result)
}

func getExperiments(c *gin.Context) {

	userID := c.GetString("user_id")

	mapping := readJSON(mappingFile)
	experiments := readJSON(experimentsFile)

	result := make(map[string]interface{})

	if v, ok := mapping[userID]; ok {

		list := v.([]interface{})

		for _, item := range list {

			m := item.(map[string]interface{})
			agentID := m["agent_id"].(string)

			for id, expRaw := range experiments {

				exp := expRaw.(map[string]interface{})

				if exp["agent_id"] == agentID {
					result[id] = exp
				}
			}
		}
	}

	c.JSON(200, result)
}
