package s3

import (
	"context"
	"fmt"
	"time"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/adigajjar/security-audit/scanner"
)

const backupPrefix = "chaos-backup/"

type RansomwareDelete struct {
	S3Client   *awss3.Client
	BucketName string
}

func (e *RansomwareDelete) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_ransomware_delete",
		TargetID:     e.BucketName,
		StartTime:    time.Now(),
		Impact:       "data_loss",
	}

	objectKeys, totalSize, err := listBucketObjects(ctx, e.S3Client, e.BucketName)
	if err != nil {
		return nil, fmt.Errorf("could not list objects: %w", err)
	}

	versioningEnabled, err := getBucketVersioning(ctx, e.S3Client, e.BucketName)
	if err != nil {
		return nil, fmt.Errorf("could not get versioning state: %w", err)
	}

	result.PreSnapshot = map[string]interface{}{
		"bucket":             e.BucketName,
		"object_count":       len(objectKeys),
		"total_size_b":       totalSize,
		"versioning_enabled": versioningEnabled,
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail:    fmt.Sprintf("bucket has %d objects (%d bytes), versioning: %v", len(objectKeys), totalSize, versioningEnabled),
	})

	if len(objectKeys) == 0 {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "skipped",
			Detail:    "bucket is empty — nothing to delete",
		})
		result.Status = "completed"
		result.Restored = true
		result.EndTime = time.Now()
		return result, nil
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "backup_started",
		Detail:    fmt.Sprintf("copying %d objects to %s prefix before deletion", len(objectKeys), backupPrefix),
	})

	backedUpKeys, err := e.backupObjects(ctx, objectKeys, result)
	if err != nil {
		// backup failed — abort entirely, do not proceed with deletion
		return nil, fmt.Errorf("backup failed — aborting experiment to prevent data loss: %w", err)
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "backup_completed",
		Detail:    fmt.Sprintf("%d objects backed up to %s — safe to proceed with deletion", len(backedUpKeys), backupPrefix),
	})

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "attack_started",
		Detail:    fmt.Sprintf("bulk deleting all %d objects — simulating ransomware", len(objectKeys)),
	})

	deleteStart := time.Now()
	deletedCount, err := bulkDeleteObjects(ctx, e.S3Client, e.BucketName, objectKeys)
	deleteTime := time.Since(deleteStart)

	if err != nil {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "delete_error",
			Detail:    fmt.Sprintf("partial delete: %v", err),
		})
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "objects_deleted",
		Detail:    fmt.Sprintf("%d/%d objects deleted in %s", deletedCount, len(objectKeys), deleteTime.Round(time.Millisecond)),
	})

	if !versioningEnabled {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "finding",
			Detail:    "versioning is OFF — without this experiment's prior backup, all objects would be permanently lost with no recovery path",
		})
	} else {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "finding",
			Detail:    "versioning is ON — objects recoverable by removing delete markers",
		})
	}

	rtoStart := time.Now()
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "recovery_started",
		Detail:    fmt.Sprintf("restoring %d objects from %s", len(objectKeys), backupPrefix),
	})

	recoveredCount, err := e.restoreFromBackup(ctx, objectKeys, result)
	rto := time.Since(rtoStart)

	if err != nil {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "recovery_error",
			Detail:    fmt.Sprintf("recovery error: %v", err),
		})
	} else {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "recovery_completed",
			Detail:    fmt.Sprintf("recovered %d/%d objects in %s (RTO)", recoveredCount, len(objectKeys), rto.Round(time.Millisecond)),
		})
	}

	e.cleanupBackup(ctx, backedUpKeys, result)

	result.PostSnapshot = map[string]interface{}{
		"objects_deleted":    deletedCount,
		"delete_time":        deleteTime.String(),
		"versioning_enabled": versioningEnabled,
		"recovered_count":    recoveredCount,
		"rto":                rto.String(),
	}
	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = recoveredCount == len(objectKeys)
	result.EndTime = time.Now()
	result.Status = "completed"

	return result, nil

}

// backupObjects copies all objects to chaos-backup/<original-key>
func (e *RansomwareDelete) backupObjects(ctx context.Context, keys []string, result *auditexperiments.ExperimentResult) ([]string, error) {
	var backedUpKeys []string
	for _, key := range keys {
		backupKey := backupPrefix + key
		_, err := e.S3Client.CopyObject(ctx, &awss3.CopyObjectInput{
			Bucket:     aws.String(e.BucketName),
			CopySource: aws.String(fmt.Sprintf("%s/%s", e.BucketName, key)),
			Key:        aws.String(backupKey),
		})
		if err != nil {
			return backedUpKeys, fmt.Errorf("failed to back up %s: %w", key, err)
		}
		backedUpKeys = append(backedUpKeys, backupKey)
	}
	return backedUpKeys, nil
}

// restoreFromBackup copies objects back from chaos-backup/<key> to their original path
func (e *RansomwareDelete) restoreFromBackup(ctx context.Context, originalKeys []string, result *auditexperiments.ExperimentResult) (int, error) {
	restoredCount := 0
	for _, key := range originalKeys {
		backupKey := backupPrefix + key
		_, err := e.S3Client.CopyObject(ctx, &awss3.CopyObjectInput{
			Bucket:     aws.String(e.BucketName),
			CopySource: aws.String(fmt.Sprintf("%s/%s", e.BucketName, backupKey)),
			Key:        aws.String(key),
		})
		if err != nil {
			result.Observations = append(result.Observations, auditexperiments.ObservationLog{
				Timestamp: time.Now(),
				Event:     "restore_failed",
				Detail:    fmt.Sprintf("could not restore %s: %v", key, err),
			})
			continue
		}
		restoredCount++
	}
	return restoredCount, nil
}

// cleanupBackup deletes all objects under chaos-backup/ prefix
func (e *RansomwareDelete) cleanupBackup(ctx context.Context, backupKeys []string, result *auditexperiments.ExperimentResult) {
	objects := make([]s3types.ObjectIdentifier, len(backupKeys))
	for i, key := range backupKeys {
		objects[i] = s3types.ObjectIdentifier{Key: aws.String(key)}
	}
	_, err := e.S3Client.DeleteObjects(ctx, &awss3.DeleteObjectsInput{
		Bucket: aws.String(e.BucketName),
		Delete: &s3types.Delete{Objects: objects},
	})
	event := "backup_cleaned"
	detail := fmt.Sprintf("deleted %d backup objects from %s", len(backupKeys), backupPrefix)
	if err != nil {
		event = "backup_cleanup_failed"
		detail = fmt.Sprintf("could not clean backup: %v — delete %s manually", err, backupPrefix)
	}
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     event,
		Detail:    detail,
	})
}

func bulkDeleteObjects(ctx context.Context, client *awss3.Client, bucket string, keys []string) (int, error) {
	deletedCount := 0
	batchSize := 1000
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}
		objects := make([]s3types.ObjectIdentifier, len(keys[i:end]))
		for j, key := range keys[i:end] {
			objects[j] = s3types.ObjectIdentifier{Key: aws.String(key)}
		}
		out, err := client.DeleteObjects(ctx, &awss3.DeleteObjectsInput{
			Bucket: aws.String(bucket),
			Delete: &s3types.Delete{Objects: objects},
		})
		if err != nil {
			return deletedCount, err
		}
		deletedCount += len(out.Deleted)
	}
	return deletedCount, nil
}

func recoverViaVersioning(ctx context.Context, client *awss3.Client, bucket string) (int, error) {
	recoveredCount := 0
	paginator := awss3.NewListObjectVersionsPaginator(client, &awss3.ListObjectVersionsInput{
		Bucket: aws.String(bucket),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return recoveredCount, err
		}
		var toDelete []s3types.ObjectIdentifier
		for _, marker := range page.DeleteMarkers {
			if aws.ToBool(marker.IsLatest) {
				toDelete = append(toDelete, s3types.ObjectIdentifier{
					Key:       marker.Key,
					VersionId: marker.VersionId,
				})
			}
		}
		if len(toDelete) == 0 {
			continue
		}
		out, err := client.DeleteObjects(ctx, &awss3.DeleteObjectsInput{
			Bucket: aws.String(bucket),
			Delete: &s3types.Delete{Objects: toDelete},
		})
		if err != nil {
			return recoveredCount, err
		}
		recoveredCount += len(out.Deleted)
	}
	return recoveredCount, nil
}

func getBucketVersioning(ctx context.Context, client *awss3.Client, bucket string) (bool, error) {
	out, err := client.GetBucketVersioning(ctx, &awss3.GetBucketVersioningInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return false, err
	}
	return string(out.Status) == "Enabled", nil
}

func SimulateRansomwareDelete(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult

	s3Data, ok := data.(scanner.S3AuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_ransomware_delete expects scanner.S3AuditResults")
	}

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %v", err)
	}

	s3Client := awss3.NewFromConfig(cfg)

	for _, bucket := range s3Data.Buckets {
		if bucket.Name == nil {
			continue
		}
		fmt.Printf("[Chaos Trigger] Starting SimulateRansomwareDelete on bucket %s\n", *bucket.Name)
		exp := RansomwareDelete{
			S3Client:   s3Client,
			BucketName: *bucket.Name,
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
