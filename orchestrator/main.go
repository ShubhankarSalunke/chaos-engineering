package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/ShubhankarSalunke/lucifer/connectors"
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

	BucketName string `json:"bucket_name,omitempty"`
	RoleARN    string `json:"role_arn,omitempty"`

	KMSKeyID      string `json:"kms_key_id,omitempty"`
	Prefix        string `json:"prefix,omitempty"`
	DeletePercent int    `json:"delete_percent,omitempty"`
	ExternalID    string `json:"external_id,omitempty"`
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

	r.Run("0.0.0.0:8000")
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

	case "s3_access_deny":
		if exp.BucketName == "" {
			c.JSON(400, gin.H{"error": "bucket_name required"})
			return
		}

		go func() {
			applyS3AccessDeny(exp.BucketName, exp.RoleARN, exp.ExternalID)
			time.Sleep(time.Duration(exp.Duration) * time.Second)
			revertS3AccessDeny(exp.BucketName, exp.RoleARN, exp.ExternalID)
		}()

	case "s3_kms_disable":
		if exp.KMSKeyID == "" {
			c.JSON(400, gin.H{"error": "kms_key_id required"})
			return
		}

		go func() {
			applyS3KMSChaos(exp.KMSKeyID, exp.RoleARN, exp.ExternalID)
			time.Sleep(time.Duration(exp.Duration) * time.Second)
			revertS3KMSChaos(exp.KMSKeyID, exp.RoleARN, exp.ExternalID)
		}()

	case "s3_object_delete":
		if exp.BucketName == "" {
			c.JSON(400, gin.H{"error": "bucket_name required"})
			return
		}

		go func() {
			applyS3DeleteChaos(exp.BucketName, exp.Prefix, exp.DeletePercent, exp.RoleARN, exp.ExternalID)
		}()

	case "s3_metadata_corrupt":
		if exp.BucketName == "" {
			c.JSON(400, gin.H{"error": "bucket_name required"})
			return
		}

		go func() {
			applyS3MetadataChaos(exp.BucketName, exp.Prefix, exp.RoleARN, exp.ExternalID)
			time.Sleep(time.Duration(exp.Duration) * time.Second)
			revertS3MetadataChaos(exp.BucketName, exp.Prefix, exp.RoleARN, exp.ExternalID)
		}()
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

/* =========================
   S3 CHAOS UTILITIES
========================= */

func getS3Client(roleArn, externalId string) *s3.Client {

	cfg, err := connectors.ConnectAws(context.TODO(), roleArn, externalId)
	if err != nil {
		fmt.Printf("Error connecting to AWS: %v\n", err)
		return nil
	}

	return s3.NewFromConfig(cfg)
}

func applyS3AccessDeny(bucketName, roleArn, externalId string) {

	client := getS3Client(roleArn, externalId)
	if client == nil {
		return
	}

	policy := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "DenyAll",
				"Effect": "Deny",
				"Principal": "*",
				"Action": "s3:*",
				"Resource": [
					"arn:aws:s3:::%s",
					"arn:aws:s3:::%s/*"
				]
			}
		]
	}`, bucketName, bucketName)

	_, err := client.PutBucketPolicy(context.TODO(), &s3.PutBucketPolicyInput{
		Bucket: aws.String(bucketName),
		Policy: aws.String(policy),
	})

	if err != nil {
		fmt.Printf("Error applying S3 chaos: %v\n", err)
	} else {
		fmt.Printf("✅ S3 Chaos applied on bucket %s (Role: %s)\n", bucketName, roleArn)
	}
}

func revertS3AccessDeny(bucketName, roleArn, externalId string) {

	client := getS3Client(roleArn, externalId)
	if client == nil {
		return
	}

	_, err := client.DeleteBucketPolicy(context.TODO(), &s3.DeleteBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})

	if err != nil {
		fmt.Printf("Error reverting S3 chaos: %v\n", err)
	} else {
		fmt.Printf("✅ S3 Chaos reverted for bucket %s\n", bucketName)
	}
}

/* =========================
   ADVANCED S3 CHAOS UTILITIES
========================= */

func getKMSClient(roleArn, externalId string) *kms.Client {

	cfg, err := connectors.ConnectAws(context.TODO(), roleArn, externalId)
	if err != nil {
		fmt.Printf("Error connecting to AWS: %v\n", err)
		return nil
	}

	return kms.NewFromConfig(cfg)
}

func applyS3KMSChaos(keyID, roleArn, externalId string) {

	client := getKMSClient(roleArn, externalId)
	if client == nil {
		return
	}

	_, err := client.DisableKey(context.TODO(), &kms.DisableKeyInput{
		KeyId: aws.String(keyID),
	})

	if err != nil {
		fmt.Printf("Error disabling KMS key: %v\n", err)
	} else {
		fmt.Printf("✅ KMS Chaos applied: Key %s disabled\n", keyID)
	}
}

func revertS3KMSChaos(keyID, roleArn, externalId string) {

	client := getKMSClient(roleArn, externalId)
	if client == nil {
		return
	}

	_, err := client.EnableKey(context.TODO(), &kms.EnableKeyInput{
		KeyId: aws.String(keyID),
	})

	if err != nil {
		fmt.Printf("Error enabling KMS key: %v\n", err)
	} else {
		fmt.Printf("✅ KMS Chaos reverted: Key %s re-enabled\n", keyID)
	}
}

func applyS3DeleteChaos(bucket, prefix string, percent int, roleArn, externalId string) {

	client := getS3Client(roleArn, externalId)
	if client == nil {
		return
	}

	if percent <= 0 {
		percent = 10 // default 10%
	}

	list, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	if err != nil {
		fmt.Printf("Error listing objects: %v\n", err)
		return
	}

	for _, obj := range list.Contents {

		if time.Now().UnixNano()%100 < int64(percent) {

			_, err := client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    obj.Key,
			})

			if err != nil {
				fmt.Printf("Error deleting object %s: %v\n", *obj.Key, err)
			} else {
				fmt.Printf("💥 Deleted object: %s\n", *obj.Key)
			}
		}
	}
}

func applyS3MetadataChaos(bucket, prefix string, roleArn, externalId string) {

	client := getS3Client(roleArn, externalId)
	if client == nil {
		return
	}

	list, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	if err != nil {
		fmt.Printf("Error listing objects: %v\n", err)
		return
	}

	for _, obj := range list.Contents {

		// Corrupt by copying to same key with different content-type
		_, err := client.CopyObject(context.TODO(), &s3.CopyObjectInput{
			Bucket:            aws.String(bucket),
			Key:               obj.Key,
			CopySource:        aws.String(fmt.Sprintf("%s/%s", bucket, *obj.Key)),
			ContentType:       aws.String("application/corrupted-chaos"),
			MetadataDirective: types.MetadataDirectiveReplace,
		})

		if err != nil {
			fmt.Printf("Error corrupting metadata for %s: %v\n", *obj.Key, err)
		} else {
			fmt.Printf("⚠️  Corrupted metadata for: %s\n", *obj.Key)
		}
	}
}

func revertS3MetadataChaos(bucket, prefix string, roleArn, externalId string) {
	// Reversion: In this simple version we just set it to application/octet-stream
	client := getS3Client(roleArn, externalId)
	if client == nil {
		return
	}

	list, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	if err != nil {
		return
	}

	for _, obj := range list.Contents {

		_, err := client.CopyObject(context.TODO(), &s3.CopyObjectInput{
			Bucket:            aws.String(bucket),
			Key:               obj.Key,
			CopySource:        aws.String(fmt.Sprintf("%s/%s", bucket, *obj.Key)),
			ContentType:       aws.String("application/octet-stream"),
			MetadataDirective: types.MetadataDirectiveReplace,
		})

		if err != nil {
			fmt.Printf("Error reverting metadata for %s: %v\n", *obj.Key, err)
		}
	}
	fmt.Printf("✅ Metadata Chaos reverted for bucket %s\n", bucket)
}
