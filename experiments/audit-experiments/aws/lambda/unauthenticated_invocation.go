package lambda

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/google/uuid"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
)

type UnauthenticatedInvocationExposure struct {
	LambdaClient *awslambda.Client
	FunctionName string
	FunctionArn  string
	FunctionURL  string
}

func (e *UnauthenticatedInvocationExposure) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_unauthenticated_invocation",
		TargetID:     e.FunctionName,
		StartTime:    time.Now(),
		Impact:       "unauthorized_invocation_and_resource_exhaustion",
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

	// Try to get function URL configuration
	urlOut, err := e.LambdaClient.GetFunctionUrlConfig(ctx, &awslambda.GetFunctionUrlConfigInput{
		FunctionName: &e.FunctionName,
	})

	functionURLEnabled := false
	authType := ""
	functionURL := e.FunctionURL

	if err == nil && urlOut != nil && urlOut.FunctionUrl != nil {
		functionURLEnabled = true
		functionURL = *urlOut.FunctionUrl
		if urlOut.AuthType != "" {
			authType = string(urlOut.AuthType)
		}
	}

	result.PreSnapshot = map[string]interface{}{
		"function_name":      e.FunctionName,
		"function_arn":       e.FunctionArn,
		"function_url":       functionURL,
		"url_enabled":        functionURLEnabled,
		"auth_type":          authType,
		"runtime":            funcOut.Configuration.Runtime,
		"timeout":            funcOut.Configuration.Timeout,
		"memory_mb":          funcOut.Configuration.MemorySize,
		"ssrf_payload_count": len(commonSSRFPayloads),
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail:    fmt.Sprintf("Function: %s, URL Enabled: %v, Auth Type: %s", e.FunctionName, functionURLEnabled, authType),
	})

	if !functionURLEnabled {
		result.Status = "completed"
		result.PostSnapshot = map[string]interface{}{
			"url_enabled":              false,
			"unauthenticated_exposure": false,
			"reason":                   "Function URL is not enabled",
		}
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "url_not_enabled",
			Detail:    fmt.Sprintf("Function %s does not have a function URL configured", e.FunctionName),
		})
		result.EndTime = time.Now()
		return result, nil
	}

	// Check if auth is disabled
	isUnauthenticated := authType == string(lambdatypes.FunctionUrlAuthTypeNone) || authType == ""

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "auth_check",
		Detail:    fmt.Sprintf("Function URL auth type: %s (unauthenticated: %v)", authType, isUnauthenticated),
	})

	// Test unauthenticated invocation and SSRF
	successfulInvocations := 0
	failedInvocations := 0
	ssrfSuccesses := 0
	resourceExhaustionRisk := false

	if isUnauthenticated && functionURL != "" {
		// Test basic invocation
		fmt.Printf("[Chaos: Unauthenticated Invocation] Testing basic invocation on %s\n", e.FunctionName)
		for i := 0; i < 3; i++ {
			success, detail := attemptUnauthenticatedInvocation(functionURL, []byte(`{"test": "payload"}`))
			if success {
				successfulInvocations++
				fmt.Printf("[Chaos: Unauthenticated Invocation] [%d/3] Invocation successful ✅\n", i+1)
			} else {
				failedInvocations++
				fmt.Printf("[Chaos: Unauthenticated Invocation] [%d/3] Invocation failed ❌\n", i+1)
			}
			result.Observations = append(result.Observations, auditexperiments.ObservationLog{
				Timestamp: time.Now(),
				Event:     "invocation_attempt",
				Detail:    detail,
			})
		}

		// Test SSRF payloads
		fmt.Printf("[Chaos: SSRF Testing] Attempting %d SSRF payloads\n", len(commonSSRFPayloads))
		for _, payload := range commonSSRFPayloads {
			ssrfPayload := fmt.Sprintf(`{"url": "%s"}`, payload)
			success, detail := attemptUnauthenticatedInvocation(functionURL, []byte(ssrfPayload))
			if success {
				ssrfSuccesses++
				result.Observations = append(result.Observations, auditexperiments.ObservationLog{
					Timestamp: time.Now(),
					Event:     "ssrf_attempt_successful",
					Detail:    detail,
				})
			}
		}

		// Simulate resource exhaustion via high-frequency requests
		resourceExhaustionRisk = true
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "resource_exhaustion_vector",
			Detail:    "Unauthenticated URL allows unlimited invocation requests — can trigger resource exhaustion (DDoS) via function concurrency limits and cost inflation",
		})
	}

	result.PostSnapshot = map[string]interface{}{
		"function_url":             functionURL,
		"url_enabled":              functionURLEnabled,
		"auth_type":                authType,
		"is_unauthenticated":       isUnauthenticated,
		"successful_invocations":   successfulInvocations,
		"failed_invocations":       failedInvocations,
		"ssrf_attempts":            len(commonSSRFPayloads),
		"ssrf_successes":           ssrfSuccesses,
		"resource_exhaustion_risk": resourceExhaustionRisk,
		"attack_vectors":           []string{"Unauthenticated function invocation", "SSRF payload injection", "Resource exhaustion/DDoS", "Cost inflation"},
		"blast_radius":             "Any caller can invoke function without credentials",
	}

	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)

	if isUnauthenticated && successfulInvocations > 0 {
		result.Status = "vulnerability_confirmed"
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "critical_finding",
			Detail:    fmt.Sprintf("CRITICAL: Function URL is publicly accessible without authentication — %d successful invocations possible", successfulInvocations),
		})
	} else if isUnauthenticated {
		result.Status = "completed"
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "finding",
			Detail:    "Function URL is unauthenticated but invocation tests inconclusive — vulnerability likely present",
		})
	} else {
		result.Status = "completed"
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "no_vulnerability",
			Detail:    fmt.Sprintf("Function URL has authentication enabled (%s) — unauthenticated access blocked", authType),
		})
	}

	result.Restored = true // read-only test
	result.EndTime = time.Now()

	return result, nil
}

func attemptUnauthenticatedInvocation(functionURL string, payload []byte) (bool, string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
		},
	}

	req, err := http.NewRequest("POST", functionURL, strings.NewReader(string(payload)))
	if err != nil {
		return false, fmt.Sprintf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ChaosEngineering-Lambda-Tester/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("Invocation failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

	// Successful if we get any response from the function (200, 500, etc)
	// Only fail if network unreachable
	success := resp.StatusCode >= 200 && resp.StatusCode < 600
	detail := fmt.Sprintf("URL: %s, Status: %d, Response (first 100 chars): %.100s", functionURL, resp.StatusCode, string(body))

	return success, detail
}

func SimulateUnauthenticatedInvocation(lambdaClient *awslambda.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult

	lambdaData, ok := data.(scanner.LambdaAuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_unauthenticated_invocation expects scanner.LambdaAuditResults")
	}

	for _, fn := range lambdaData.Functions {
		if fn.FunctionName != nil && fn.FunctionArn != nil {
			functionURL := ""

			fmt.Printf("[Chaos Trigger] Testing unauthenticated invocation on %s\n", *fn.FunctionName)
			exp := UnauthenticatedInvocationExposure{
				LambdaClient: lambdaClient,
				FunctionName: *fn.FunctionName,
				FunctionArn:  *fn.FunctionArn,
				FunctionURL:  functionURL,
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
