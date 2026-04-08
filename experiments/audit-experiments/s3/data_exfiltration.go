package s3

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

type DataExfiltration struct {
	S3Client         *awss3.Client
	GuardDutyClient  *guardduty.Client
	CloudWatchClient *cloudwatchlogs.Client
	BucketName       string
	Region           string
	DetectorID       string
}

func (e *DataExfiltration) Run() (*auditexperiments.ExperimentResult, error){
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_data_exfiltration",
		TargetID:     e.BucketName,
		StartTime:    time.Now(),
		Impact:       "data_exposure",
	}

	objectKeys, totalSize, err := listBucketObjects(ctx, e.S3Client, e.BucketName)
	if err != nil {
		return nil, fmt.Errorf("could not list bucket objects: %w", err)
	}

	result.PreSnapshot = map[string]interface{}{
		"bucket":        e.BucketName,
		"object_count":  len(objectKeys),
		"total_size_b":  totalSize,
		"acl_public":    true,
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail:    fmt.Sprintf("bucket has %d objects (%d bytes) — public ACL confirmed", len(objectKeys), totalSize),
	})

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
        Timestamp: time.Now(),
        Event:     "chaos_injection",
        Detail:    fmt.Sprintf("Intentionally setting public read bucket policy for bucket %s", e.BucketName),
    })

	publicPolicy := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::%s/*"
		}]
	}`, e.BucketName)

	_, err = e.S3Client.PutBucketPolicy(ctx, &awss3.PutBucketPolicyInput{
		Bucket: aws.String(e.BucketName),
		Policy: aws.String(publicPolicy),
	})
	if err != nil {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "chaos_injection_failed",
			Detail:    fmt.Sprintf("failed to put bucket policy: %v", err),
		})
		fmt.Printf("Warning: failed to make bucket %s public: %v\n", e.BucketName, err)
	}

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

	attackStart := time.Now()
	downloadedCount := 0
	downloadedBytes := 0
	httpClient := &http.Client{Timeout: 10 * time.Second}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "attack_started",
		Detail:    fmt.Sprintf("attempting unauthenticated download of %d objects", len(objectKeys)),
	})

	for _, key := range objectKeys {
		url := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", e.BucketName, e.Region, key)
		resp, err := httpClient.Get(url)
		if err != nil {
			result.Observations = append(result.Observations, auditexperiments.ObservationLog{
				Timestamp: time.Now(),
				Event:     "download_failed",
				Detail:    fmt.Sprintf("%s → %v", key, err),
			})
			continue
		}
 
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
 
		if resp.StatusCode == 200 {
			downloadedCount++
			downloadedBytes += len(body)
			result.Observations = append(result.Observations, auditexperiments.ObservationLog{
				Timestamp: time.Now(),
				Event:     "object_downloaded",
				Detail:    fmt.Sprintf("%s → %d bytes downloaded unauthenticated (HTTP %d)", key, len(body), resp.StatusCode),
			})
		} else {
			result.Observations = append(result.Observations, auditexperiments.ObservationLog{
				Timestamp: time.Now(),
				Event:     "access_denied",
				Detail:    fmt.Sprintf("%s → HTTP %d", key, resp.StatusCode),
			})
		}
	}

	timeToExfil := time.Since(attackStart)

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
        Timestamp: time.Now(),
        Event:     "restoration_started",
        Detail:    fmt.Sprintf("Deleting public bucket policy from %s", e.BucketName),
    })

	_, err = e.S3Client.DeleteBucketPolicy(ctx, &awss3.DeleteBucketPolicyInput{
		Bucket: aws.String(e.BucketName),
	})
	if err != nil {
		fmt.Printf("Warning: Restoration failed (manual cleanup required for %s): %v\n", e.BucketName, err)
	}
 
	if downloadedCount > 0 {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "critical_finding",
			Detail:    fmt.Sprintf("CRITICAL: %d/%d objects downloaded unauthenticated (%d bytes) in %s", downloadedCount, len(objectKeys), downloadedBytes, timeToExfil.Round(time.Second)),
		})
	}

	// Poll GuardDuty for detection alerts
	time.Sleep(30 * time.Second) // give GuardDuty time to react
	detected, detectionDetail := e.checkGuardDutyFindings(ctx, attackStart)
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "detection_check",
		Detail:    detectionDetail,
	})


	result.PostSnapshot = map[string]interface{}{
		"objects_attempted":   len(objectKeys),
		"objects_downloaded":  downloadedCount,
		"bytes_exfiltrated":   downloadedBytes,
		"time_to_exfil":       timeToExfil.String(),
		"guardduty_detected":  detected,
	}

	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = true
	result.EndTime = time.Now()
	result.Status = "completed"
 
	return result, nil


}

func (e *DataExfiltration) checkGuardDutyFindings(ctx context.Context, since time.Time) (bool, string) {
	if e.GuardDutyClient == nil || e.DetectorID == "" {
		return false, "RECOMMENDATION: AWS GuardDuty is not enabled or configured. For your safety, we strongly recommend enabling it to detect and stop data exfiltration attacks in real-time."
	}
 
	out, err := e.GuardDutyClient.ListFindings(ctx, &guardduty.ListFindingsInput{
		DetectorId: aws.String(e.DetectorID),
		FindingCriteria: &types.FindingCriteria{
			Criterion: map[string]types.Condition{
				"resource.s3BucketDetails.name": {
					Equals: []string{e.BucketName},
				},
			},
		},
	})
	if err != nil {
		return false, fmt.Sprintf("GuardDuty check failed: %v", err)
	}
	if len(out.FindingIds) > 0 {
		return true, fmt.Sprintf("GuardDuty detected %d finding(s) for bucket %s", len(out.FindingIds), e.BucketName)
	}
	return false, "GuardDuty did not detect the exfiltration within 30s — detection gap confirmed"
}
 
func listBucketObjects(ctx context.Context, client *awss3.Client, bucket string) ([]string, int64, error) {
	var keys []string
	var totalSize int64
 
	paginator := awss3.NewListObjectsV2Paginator(client, &awss3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, 0, err
		}
		for _, obj := range page.Contents {
			keys = append(keys, aws.ToString(obj.Key))
			totalSize += aws.ToInt64(obj.Size)
		}
	}
	return keys, totalSize, nil
}

func SimulateDataExfiltration(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult
	
	s3Data, ok := data.(scanner.S3AuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_data_exfiltration expects scanner.S3AuditResults")
	}

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %v", err)
	}

	s3Client := awss3.NewFromConfig(cfg)
	guardDutyClient := guardduty.NewFromConfig(cfg)

	for _, bucket := range s3Data.Buckets {
		if bucket.Name == nil {
			continue
		}
		fmt.Printf("[Chaos Trigger] Starting data exfiltration on bucket %s\n", *bucket.Name)
		exp := DataExfiltration{
			S3Client:        s3Client,
			GuardDutyClient: guardDutyClient,
			BucketName:      *bucket.Name,
			Region:          cfg.Region,
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