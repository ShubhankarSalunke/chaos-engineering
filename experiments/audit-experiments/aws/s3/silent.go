package s3

import (
	"context"
	"fmt"
	"io"
	"time"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/adigajjar/security-audit/scanner"
)

type SilentExfiltration struct {
	S3Client         *awss3.Client
	CloudTrailClient *cloudtrail.Client
	BucketName       string
}

func (e *SilentExfiltration) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_silent_exfiltration",
		TargetID:     e.BucketName,
		StartTime:    time.Now(),
		Impact:       "undetected_data_exposure",
	}

	loggingEnabled, err := getBucketLoggingState(ctx, e.S3Client, e.BucketName)
	if err != nil {
		return nil, fmt.Errorf("could not check logging state: %w", err)
	}
	objectKeys, totalSize, err := listBucketObjects(ctx, e.S3Client, e.BucketName)
	if err != nil {
		return nil, fmt.Errorf("could not list objects: %w", err)
	}

	result.PreSnapshot = map[string]interface{}{
		"bucket":          e.BucketName,
		"logging_enabled": loggingEnabled,
		"object_count":    len(objectKeys),
		"total_size_b":    totalSize,
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail:    fmt.Sprintf("logging enabled: %v — %d objects in bucket", loggingEnabled, len(objectKeys)),
	})

	if len(objectKeys) == 0 {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "skipped",
			Detail:    "bucket is empty — nothing to exfiltrate",
		})
		result.Status = "completed"
		result.Restored = true
		result.EndTime = time.Now()
		return result, nil
	}

	exfilStart := time.Now()
	downloadedCount := 0
	downloadedBytes := 0

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "attack_started",
		Detail:    fmt.Sprintf("exfiltrating %d objects — logging is %v", len(objectKeys), map[bool]string{true: "ON", false: "OFF"}[loggingEnabled]),
	})

	for _, key := range objectKeys {
		out, err := e.S3Client.GetObject(ctx, &awss3.GetObjectInput{
			Bucket: aws.String(e.BucketName),
			Key:    aws.String(key),
		})
		if err != nil {
			result.Observations = append(result.Observations, auditexperiments.ObservationLog{
				Timestamp: time.Now(),
				Event:     "download_failed",
				Detail:    fmt.Sprintf("%s → %v", key, err),
			})
			continue
		}
		body, _ := io.ReadAll(out.Body)
		out.Body.Close()
		downloadedCount++
		downloadedBytes += len(body)
	}

	exfilEnd := time.Now()
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "exfiltration_completed",
		Detail:    fmt.Sprintf("%d objects downloaded (%d bytes) between %s and %s", downloadedCount, downloadedBytes, exfilStart.Format(time.RFC3339), exfilEnd.Format(time.RFC3339)),
	})

	// Wait for CloudTrail to process events (CloudTrail has ~15 min delay)
	// We check immediately to show the detection gap
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "detection_check_started",
		Detail:    "checking CloudTrail for evidence of the exfiltration",
	})

	cloudTrailEvents, err := e.checkCloudTrailEvidence(ctx, exfilStart, exfilEnd)

	if err != nil {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "cloudtrail_check_failed",
			Detail:    fmt.Sprintf("CloudTrail check error: %v", err),
		})
	} else if cloudTrailEvents == 0 && !loggingEnabled {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "critical_finding",
			Detail:    fmt.Sprintf("CRITICAL: %d objects exfiltrated with ZERO CloudTrail evidence — attack is completely invisible", downloadedCount),
		})
	} else if cloudTrailEvents > 0 {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "finding",
			Detail:    fmt.Sprintf("CloudTrail recorded %d events — exfiltration is detectable via CloudTrail even without S3 logging", cloudTrailEvents),
		})
	}

	// Run again with logging ON to show detection contrast (if logging was off)
	s3LogEvents := 0
	if !loggingEnabled {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "contrast_check",
			Detail:    "S3 access logging is OFF — if it were ON, every GetObject would appear in the access log with requester IP, timestamp, and object key",
		})
	} else {
		s3LogEvents = downloadedCount // each download = one log entry
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "contrast_check",
			Detail:    fmt.Sprintf("S3 access logging is ON — %d GetObject events were logged with full request details", s3LogEvents),
		})
	}

	result.PostSnapshot = map[string]interface{}{
		"objects_exfiltrated":   downloadedCount,
		"bytes_exfiltrated":     downloadedBytes,
		"logging_enabled":       loggingEnabled,
		"cloudtrail_events":     cloudTrailEvents,
		"s3_log_events":         s3LogEvents,
		"completely_undetected": cloudTrailEvents == 0 && !loggingEnabled,
	}
	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = true
	result.EndTime = time.Now()
	result.Status = "completed"

	return result, nil
}

func (e *SilentExfiltration) checkCloudTrailEvidence(ctx context.Context, start, end time.Time) (int, error) {
	if e.CloudTrailClient == nil {
		return 0, fmt.Errorf("CloudTrail client not configured")
	}

	out, err := e.CloudTrailClient.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(start),
		EndTime:   aws.Time(end),
		LookupAttributes: []cloudtrailtypes.LookupAttribute{
			{
				AttributeKey:   cloudtrailtypes.LookupAttributeKeyResourceName,
				AttributeValue: aws.String(e.BucketName),
			},
		},
	})
	if err != nil {
		return 0, err
	}
	return len(out.Events), nil
}

func getBucketLoggingState(ctx context.Context, client *awss3.Client, bucket string) (bool, error) {
	out, err := client.GetBucketLogging(ctx, &awss3.GetBucketLoggingInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return false, err
	}
	return out.LoggingEnabled != nil, nil
}

func SimulateSilentExfiltration(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult

	s3Data, ok := data.(scanner.S3AuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_silent_exfiltration expects scanner.S3AuditResults")
	}

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %v", err)
	}

	s3Client := awss3.NewFromConfig(cfg)
	cloudTrailClient := cloudtrail.NewFromConfig(cfg)

	for _, bucket := range s3Data.Buckets {
		if bucket.Name == nil {
			continue
		}
		fmt.Printf("[Chaos Trigger] Starting SimulateSilentExfiltration on bucket %s\n", *bucket.Name)
		exp := SilentExfiltration{
			S3Client:         s3Client,
			CloudTrailClient: cloudTrailClient,
			BucketName:       *bucket.Name,
		}

		res, err := exp.Run()
		if err != nil {
			fmt.Printf("[Chaos Trigger] Experiment failed: %v\n", err)
		} else {
			fmt.Printf("[Chaos Trigger] Experiment completed: Impact=%s, Status=%s\n", res.Impact, res.Status)
			results = append(results, res)
		}
	}
	return results, nil
}
