package lambda

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/google/uuid"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
)

type SilentFunctionFailureExposure struct {
	LambdaClient *awslambda.Client
	SQSClient    *sqs.Client
	FunctionName string
	FunctionArn  string
}

func (e *SilentFunctionFailureExposure) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_silent_function_failure",
		TargetID:     e.FunctionName,
		StartTime:    time.Now(),
		Impact:       "data_pipeline_gap",
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

	// Get event source mappings to check for DLQ configuration
	eventSrcOut, err := e.LambdaClient.ListEventSourceMappings(ctx, &awslambda.ListEventSourceMappingsInput{
		FunctionName: &e.FunctionName,
	})

	eventSources := []string{}
	hasDLQ := false
	totalEventSources := 0

	if err == nil && eventSrcOut != nil && eventSrcOut.EventSourceMappings != nil {
		totalEventSources = len(eventSrcOut.EventSourceMappings)
		for _, mapping := range eventSrcOut.EventSourceMappings {
			if mapping.EventSourceArn != nil {
				eventSources = append(eventSources, *mapping.EventSourceArn)
			}
			// Check for DLQ (dead letter queue)
			if mapping.FunctionResponseTypes != nil && len(mapping.FunctionResponseTypes) > 0 {
				hasDLQ = true
			}
		}
	}

	// Get concurrency configuration
	concurrencyOut, err := e.LambdaClient.GetFunctionConcurrency(ctx, &awslambda.GetFunctionConcurrencyInput{
		FunctionName: &e.FunctionName,
	})

	reservedConcurrency := int32(0)
	if err == nil && concurrencyOut != nil {
		if concurrencyOut.ReservedConcurrentExecutions != nil {
			reservedConcurrency = *concurrencyOut.ReservedConcurrentExecutions
		}
	}

	result.PreSnapshot = map[string]interface{}{
		"function_name":         e.FunctionName,
		"function_arn":          e.FunctionArn,
		"runtime":               funcOut.Configuration.Runtime,
		"timeout":               funcOut.Configuration.Timeout,
		"event_source_count":    totalEventSources,
		"event_sources":         eventSources,
		"dlq_configured":        hasDLQ,
		"concurrent_executions": reservedConcurrency,
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail:    fmt.Sprintf("Function: %s, Event sources: %d, DLQ configured: %v", e.FunctionName, totalEventSources, hasDLQ),
	})

	// Analyze DLQ configuration
	dlqConfigured := false
	dlqType := ""
	dlqArn := ""

	if totalEventSources > 0 {
		for _, mapping := range eventSrcOut.EventSourceMappings {
			if mapping.DestinationConfig != nil && mapping.DestinationConfig.OnFailure != nil && mapping.DestinationConfig.OnFailure.Destination != nil {
				dlqConfigured = true
				dlqArn = *mapping.DestinationConfig.OnFailure.Destination
				if containsSubstring(dlqArn, "sqs") {
					dlqType = "SQS"
				} else if containsSubstring(dlqArn, "sns") {
					dlqType = "SNS"
				}
			}
		}
	}

	silentFailureRisk := totalEventSources > 0 && !dlqConfigured
	dataLossRisk := "NONE"
	if silentFailureRisk {
		dataLossRisk = "HIGH"
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "event_source_analysis",
		Detail:    fmt.Sprintf("Function has %d asynchronous event source(s) — DLQ configured: %v", totalEventSources, dlqConfigured),
	})

	if silentFailureRisk {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "critical_finding",
			Detail:    "CRITICAL: No DLQ/on-failure destination configured — function failures will silently drop events after max retries, creating undetected data pipeline gaps",
		})

		retryCount := 2 // default retry count for asynchronous invocations
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "silent_failure_scenario",
			Detail:    fmt.Sprintf("Failure scenario: Event arrives → Function fails → Retry %d times → Event dropped silently (no DLQ to capture), Data permanently lost", retryCount),
		})
	} else if totalEventSources == 0 {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "no_event_sources",
			Detail:    "Function has no asynchronous event sources configured — DLQ not applicable for synchronous invocations",
		})
		dataLossRisk = "N/A"
	} else if dlqConfigured {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "dlq_configured",
			Detail:    fmt.Sprintf("DLQ configured with type %s at %s — failed events will be captured", dlqType, dlqArn),
		})
	}

	result.PostSnapshot = map[string]interface{}{
		"event_source_count":      totalEventSources,
		"event_sources_list":      eventSources,
		"dlq_configured":          dlqConfigured,
		"dlq_type":                dlqType,
		"dlq_arn":                 dlqArn,
		"silent_failure_risk":     silentFailureRisk,
		"data_loss_risk":          dataLossRisk,
		"reserved_concurrency":    reservedConcurrency,
		"max_retry_attempts":      2,
		"impact_if_fails":         "All events after max retries are LOST permanently — no audit trail, monitoring gap",
		"recommended_dlq":         "Configure SQS DLQ or SNS topic for on-failure destination",
		"monitoring_requirements": []string{"Monitor DLQ message age", "Alert on DLQ message arrival", "Track end-to-end latency", "Monitor function error rates"},
	}

	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)

	if silentFailureRisk {
		result.Status = "vulnerability_confirmed"
	} else {
		result.Status = "completed"
	}

	result.Restored = true // read-only assessment
	result.EndTime = time.Now()

	return result, nil
}

func SimulateSilentFunctionFailure(lambdaClient *awslambda.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult

	lambdaData, ok := data.(scanner.LambdaAuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_silent_function_failure expects scanner.LambdaAuditResults")
	}

	// Get SQS client for potential DLQ validation
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	sqsClient := sqs.NewFromConfig(cfg)

	for _, fn := range lambdaData.Functions {
		if fn.FunctionName != nil && fn.FunctionArn != nil {
			fmt.Printf("[Chaos Trigger] Assessing silent failure risk on %s\n", *fn.FunctionName)
			exp := SilentFunctionFailureExposure{
				LambdaClient: lambdaClient,
				SQSClient:    sqsClient,
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
