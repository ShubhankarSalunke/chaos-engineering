package lambda

import (
	"context"
	"fmt"
	"time"

	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/google/uuid"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
)

type EnvVarSecretHarvestExposure struct {
	LambdaClient *awslambda.Client
	FunctionName string
	FunctionArn  string
}

func (e *EnvVarSecretHarvestExposure) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_env_var_secret_harvest",
		TargetID:     e.FunctionName,
		StartTime:    time.Now(),
		Impact:       "credential_exposure",
	}

	// Get Lambda function details
	funcOut, err := e.LambdaClient.GetFunction(ctx, &awslambda.GetFunctionInput{
		FunctionName: &e.FunctionName,
	})
	if err != nil {
		result.Status = "failed"
		result.EndTime = time.Now()
		result.PostSnapshot = map[string]interface{}{
			"error": "could not get Lambda function details",
		}
		return result, fmt.Errorf("could not get Lambda function %s: %w", e.FunctionName, err)
	}

	if funcOut.Configuration == nil {
		result.Status = "failed"
		result.EndTime = time.Now()
		result.PostSnapshot = map[string]interface{}{
			"error": "Lambda function configuration is empty",
		}
		return result, fmt.Errorf("Lambda function %s has no configuration", e.FunctionName)
	}

	envVars := make(map[string]string)
	if funcOut.Configuration.Environment != nil && funcOut.Configuration.Environment.Variables != nil {
		envVars = funcOut.Configuration.Environment.Variables
	}

	result.PreSnapshot = map[string]interface{}{
		"function_name":        e.FunctionName,
		"function_arn":         e.FunctionArn,
		"runtime":              funcOut.Configuration.Runtime,
		"handler":              funcOut.Configuration.Handler,
		"environment_vars_set": len(envVars),
		"timeout":              funcOut.Configuration.Timeout,
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail:    fmt.Sprintf("Function: %s, Environment variables found: %d", e.FunctionName, len(envVars)),
	})

	// Scan for sensitive environment variables
	secretsFound := make(map[string]string)
	suspiciousVars := make(map[string]string)

	for key, value := range envVars {
		// Exact matches for known secret patterns
		for _, secretKey := range commonLambdaEnvVars {
			if key == secretKey {
				secretsFound[key] = value
				result.Observations = append(result.Observations, auditexperiments.ObservationLog{
					Timestamp: time.Now(),
					Event:     "secret_exposed",
					Detail:    fmt.Sprintf("CRITICAL: Environment variable '%s' contains sensitive data — exposed in function configuration", key),
				})
			}
		}

		// Pattern matching for suspicious variable names
		if isSuspiciousVarName(key) {
			suspiciousVars[key] = value
			result.Observations = append(result.Observations, auditexperiments.ObservationLog{
				Timestamp: time.Now(),
				Event:     "suspicious_variable",
				Detail:    fmt.Sprintf("WARNING: Environment variable '%s' matches secret pattern — likely contains credentials", key),
			})
		}
	}

	// Simulate error-based exfiltration path
	errorExfiltrationRisk := false
	if len(secretsFound) > 0 || len(suspiciousVars) > 0 {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "error_path_analysis",
			Detail:    "Lambda function errors may leak environment variables through exception stack traces or error responses to caller",
		})
		errorExfiltrationRisk = true
	}

	result.PostSnapshot = map[string]interface{}{
		"environment_vars_count":      len(envVars),
		"critical_secrets_found":      len(secretsFound),
		"suspicious_vars_found":       len(suspiciousVars),
		"secrets_list":                secretsFound,
		"suspicious_vars_list":        suspiciousVars,
		"error_exfiltration_risk":     errorExfiltrationRisk,
		"exposure_method":             "Function configuration (visible to users with lambda:GetFunction), Error responses, CloudWatch logs",
		"credential_harvest_feasible": len(secretsFound) > 0,
	}

	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)

	if len(secretsFound) > 0 {
		result.Status = "vulnerability_confirmed"
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "critical_finding",
			Detail:    fmt.Sprintf("CRITICAL: %d secret credentials exposed in environment variables — immediate remediation required", len(secretsFound)),
		})
	} else if len(suspiciousVars) > 0 {
		result.Status = "completed"
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "finding",
			Detail:    fmt.Sprintf("WARNING: %d suspicious environment variables detected — likely contain sensitive data", len(suspiciousVars)),
		})
	} else {
		result.Status = "completed"
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "no_secrets",
			Detail:    "No obvious secrets found in environment variables — may be using AWS Secrets Manager or Parameter Store",
		})
	}

	result.Restored = true // read-only scan
	result.EndTime = time.Now()

	return result, nil
}

func isSuspiciousVarName(name string) bool {
	suspiciousPatterns := []string{
		"PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL",
		"AUTH", "API", "PRIVATE", "OAUTH", "APIKEY",
		"APITOKEN", "ACCESSKEY", "SECRETKEY",
	}

	for _, pattern := range suspiciousPatterns {
		if containsSubstring(name, pattern) {
			return true
		}
	}
	return false
}

func SimulateEnvVarSecretHarvest(lambdaClient *awslambda.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult

	lambdaData, ok := data.(scanner.LambdaAuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_env_var_secret_harvest expects scanner.LambdaAuditResults")
	}

	for _, fn := range lambdaData.Functions {
		if fn.FunctionName != nil && fn.FunctionArn != nil {
			fmt.Printf("[Chaos Trigger] Starting environment variable secret harvest on %s\n", *fn.FunctionName)
			exp := EnvVarSecretHarvestExposure{
				LambdaClient: lambdaClient,
				FunctionName: *fn.FunctionName,
				FunctionArn:  *fn.FunctionArn,
			}
			res, err := exp.Run()
			if err != nil {
				fmt.Printf("[Chaos Trigger] Experiment failed: %v\n", err)
			} else {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
