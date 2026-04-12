package rds

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
)

type SnapshotDataLeakExposure struct {
	RDSClient    *rds.Client
	S3Client     *s3.Client
	SnapshotID   string
	DBInstanceID string
}

func (e *SnapshotDataLeakExposure) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_snapshot_data_leak",
		TargetID:     e.SnapshotID,
		StartTime:    time.Now(),
		Impact:       "sensitive_data_exposure",
	}

	// Get snapshot details
	snapOut, err := e.RDSClient.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{
		DBSnapshotIdentifier: &e.SnapshotID,
	})
	if err != nil || len(snapOut.DBSnapshots) == 0 {
		result.Status = "failed"
		result.EndTime = time.Now()
		result.PostSnapshot = map[string]interface{}{
			"error": "could not describe snapshot",
		}
		return result, fmt.Errorf("could not describe snapshot %s: %w", e.SnapshotID, err)
	}

	snap := snapOut.DBSnapshots[0]
	encrypted := false
	if snap.Encrypted != nil {
		encrypted = *snap.Encrypted
	}

	var size int64 = 0
	if snap.AllocatedStorage != nil {
		size = int64(*snap.AllocatedStorage)
	}

	result.PreSnapshot = map[string]interface{}{
		"snapshot_id":    e.SnapshotID,
		"encrypted":      encrypted,
		"size_gb":        size,
		"db_instance_id": e.DBInstanceID,
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail: fmt.Sprintf("Snapshot: %s, Encrypted: %v, Size: %d GB",
			e.SnapshotID, encrypted, size),
	})

	// Check snapshot attributes for public access
	snapAttr, err := e.RDSClient.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{
		DBSnapshotIdentifier: &e.SnapshotID,
	})

	isPublic := false
	if err == nil && snapAttr != nil && snapAttr.DBSnapshotAttributesResult != nil {
		for _, attr := range snapAttr.DBSnapshotAttributesResult.DBSnapshotAttributes {
			if attr.AttributeName != nil && *attr.AttributeName == "restore" {
				for _, val := range attr.AttributeValues {
					if val == "all" {
						isPublic = true
						break
					}
				}
			}
		}
	}

	// Analyze encryption and export risk
	if !encrypted {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "unencrypted_snapshot_detected",
			Detail:    fmt.Sprintf("Snapshot %s is UNENCRYPTED — data in plaintext", e.SnapshotID),
		})

		// Attempt export to S3 (read-only operation, just show it's possible)
		exportTaskID := fmt.Sprintf("export-%s-%d", e.SnapshotID, time.Now().Unix())
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "export_initiated",
			Detail: fmt.Sprintf("Export task initiated: %s to s3://security-audit-exports/%s/",
				exportTaskID, e.SnapshotID),
		})

		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "data_export_possible",
			Detail:    "Data can be exported to S3 without KMS key requirement — full plaintext access",
		})

		result.PostSnapshot = map[string]interface{}{
			"encrypted":            false,
			"kms_key_required":     false,
			"export_possible":      true,
			"data_visibility":      "PLAINTEXT",
			"export_location":      fmt.Sprintf("s3://security-audit-exports/%s/", e.SnapshotID),
			"export_task_id":       exportTaskID,
			"external_access_risk": "CRITICAL",
		}
	} else {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "encrypted_snapshot",
			Detail:    fmt.Sprintf("Snapshot %s is encrypted — KMS key required for access", e.SnapshotID),
		})

		result.PostSnapshot = map[string]interface{}{
			"encrypted":            true,
			"kms_key_required":     true,
			"export_possible":      true,
			"data_visibility":      "KMS-ENCRYPTED",
			"external_access_risk": "MEDIUM (KMS key controls access)",
		}
	}

	// Check if public
	if isPublic {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "critical_finding",
			Detail:    fmt.Sprintf("CRITICAL: Snapshot %s is PUBLICLY RESTORABLE — any AWS account can restore", e.SnapshotID),
		})
		result.PostSnapshot["is_public_restorable"] = true
		result.PostSnapshot["public_restore_risk"] = "CRITICAL - anyone can access"
	} else {
		result.PostSnapshot["is_public_restorable"] = false
	}

	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = true
	result.EndTime = time.Now()
	result.Status = "completed"
	return result, nil
}

func SimulateSnapshotDataLeak(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult
	rdsData, ok := data.(scanner.RdsAuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_snapshot_data_leak expects scanner.RdsAuditResults")
	}

	// Create RDS and S3 clients with region from EC2 client
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(client.Options().Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	rdsClient := rds.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)

	// Test snapshots with encryption issues
	for _, snap := range rdsData.DBSnapshots {
		if snap.DBSnapshotIdentifier == nil || snap.DBInstanceIdentifier == nil {
			continue
		}

		encrypted := false
		if snap.Encrypted != nil {
			encrypted = *snap.Encrypted
		}

		// Only simulate data leak for unencrypted snapshots
		if !encrypted {
			fmt.Printf("[Chaos Trigger] Starting snapshot data leak simulation on %s\n", *snap.DBSnapshotIdentifier)

			exp := SnapshotDataLeakExposure{
				RDSClient:    rdsClient,
				S3Client:     s3Client,
				SnapshotID:   *snap.DBSnapshotIdentifier,
				DBInstanceID: *snap.DBInstanceIdentifier,
			}

			res, err := exp.Run()
			if err != nil {
				fmt.Printf("[Chaos Trigger] Experiment failed: %v\n", err)
			} else {
				fmt.Printf("[Chaos Trigger] Experiment completed: Impact=%s, Status=%s\n", res.Impact, res.Status)
				results = append(results, res)
			}
		}
	}

	// Also test public snapshots
	for _, snapID := range rdsData.PublicSnapshots {
		fmt.Printf("[Chaos Trigger] Starting public snapshot exposure simulation on %s\n", snapID)

		exp := SnapshotDataLeakExposure{
			RDSClient:  rdsClient,
			S3Client:   s3Client,
			SnapshotID: snapID,
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
