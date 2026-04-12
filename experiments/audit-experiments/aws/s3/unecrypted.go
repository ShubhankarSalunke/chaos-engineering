package s3

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

type UnencryptedWrite struct {
	S3Client     *awss3.Client
	ConfigClient *configservice.Client
	BucketName   string
}

// test objects to upload without encryption
var testObjects = []struct{ key, content string }{
	{"chaos-test/plaintext-config.txt", "DB_PASSWORD=supersecret\nAPI_KEY=abc123\nSECRET_TOKEN=xyz789"},
	{"chaos-test/plaintext-data.txt", "user_id,email,ssn\n1,test@example.com,123-45-6789"},
}

func (e *UnencryptedWrite) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_unencrypted_write",
		TargetID:     e.BucketName,
		StartTime:    time.Now(),
		Impact:       "data_exposure",
	}

	// Pre snapshot — check current encryption config
	encConfig, err := getBucketEncryptionConfig(ctx, e.S3Client, e.BucketName)
	if err != nil {
		return nil, fmt.Errorf("could not get encryption config: %w", err)
	}

	result.PreSnapshot = map[string]interface{}{
		"bucket":                 e.BucketName,
		"encryption_enforced":    encConfig["enforced"],
		"default_encryption":     encConfig["algorithm"],
	}
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail:    fmt.Sprintf("bucket encryption enforced: %v, algorithm: %v", encConfig["enforced"], encConfig["algorithm"]),
	})

	// Attack — upload objects without any encryption headers
	uploadedKeys := []string{}
	unencryptedCount := 0

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "attack_started",
		Detail:    fmt.Sprintf("uploading %d plaintext objects without encryption headers", len(testObjects)),
	})

	for _, obj := range testObjects {
		_, err := e.S3Client.PutObject(ctx, &awss3.PutObjectInput{
			Bucket: aws.String(e.BucketName),
			Key:    aws.String(obj.key),
			Body:   bytes.NewReader([]byte(obj.content)),
			// deliberately no ServerSideEncryption field
		})
		if err != nil {
			// if upload was rejected — bucket policy is enforcing encryption
			if strings.Contains(err.Error(), "InvalidRequest") || strings.Contains(err.Error(), "AccessDenied") {
				result.Observations = append(result.Observations, auditexperiments.ObservationLog{
					Timestamp: time.Now(),
					Event:     "upload_rejected",
					Detail:    fmt.Sprintf("%s → rejected by bucket policy — encryption enforced at policy level", obj.key),
				})
			} else {
				result.Observations = append(result.Observations, auditexperiments.ObservationLog{
					Timestamp: time.Now(),
					Event:     "upload_failed",
					Detail:    fmt.Sprintf("%s → %v", obj.key, err),
				})
			}
			continue
		}

		// Upload succeeded — verify the object's encryption headers
		headOut, err := e.S3Client.HeadObject(ctx, &awss3.HeadObjectInput{
			Bucket: aws.String(e.BucketName),
			Key:    aws.String(obj.key),
		})

		uploadedKeys = append(uploadedKeys, obj.key)

		if err == nil && headOut.ServerSideEncryption == "" {
			unencryptedCount++
			result.Observations = append(result.Observations, auditexperiments.ObservationLog{
				Timestamp: time.Now(),
				Event:     "critical_finding",
				Detail:    fmt.Sprintf("CRITICAL: %s uploaded and stored WITHOUT encryption — no SSE headers present", obj.key),
			})
		} else if err == nil {
			result.Observations = append(result.Observations, auditexperiments.ObservationLog{
				Timestamp: time.Now(),
				Event:     "default_encryption_applied",
				Detail:    fmt.Sprintf("%s uploaded without headers but bucket applied default encryption: %s", obj.key, string(headOut.ServerSideEncryption)),
			})
		}
	}

	// Check AWS Config for violation flagging
	time.Sleep(10 * time.Second)
	configFlagged, configDetail := e.checkConfigRule(ctx)
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "config_rule_check",
		Detail:    configDetail,
	})

	// Restore — delete the test objects
	for _, key := range uploadedKeys {
		e.S3Client.DeleteObject(ctx, &awss3.DeleteObjectInput{
			Bucket: aws.String(e.BucketName),
			Key:    aws.String(key),
		})
	}
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "restored",
		Detail:    fmt.Sprintf("deleted %d test objects", len(uploadedKeys)),
	})

	result.PostSnapshot = map[string]interface{}{
		"objects_uploaded":        len(uploadedKeys),
		"unencrypted_objects":     unencryptedCount,
		"config_rule_flagged":     configFlagged,
	}
	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = true
	result.EndTime = time.Now()
	result.Status = "completed"

	return result, nil
}

func (e *UnencryptedWrite) checkConfigRule(ctx context.Context) (bool, string) {
	if e.ConfigClient == nil {
		return false, "AWS Config client not configured — skipping config rule check"
	}
	out, err := e.ConfigClient.DescribeComplianceByResource(ctx, &configservice.DescribeComplianceByResourceInput{
		ResourceType: aws.String("AWS::S3::Bucket"),
		ResourceId:   aws.String(e.BucketName),
	})
	if err != nil {
		return false, fmt.Sprintf("Config rule check failed: %v", err)
	}
	for _, result := range out.ComplianceByResources {
		if result.Compliance != nil && result.Compliance.ComplianceType == configtypes.ComplianceTypeNonCompliant {
			return true, "AWS Config flagged bucket as NON_COMPLIANT for encryption rule"
		}
	}
	return false, "AWS Config did not flag the violation — Config rule may not be enabled"
}
 
func getBucketEncryptionConfig(ctx context.Context, client *awss3.Client, bucket string) (map[string]interface{}, error) {
	out, err := client.GetBucketEncryption(ctx, &awss3.GetBucketEncryptionInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		// no encryption configured at all
		return map[string]interface{}{
			"enforced":  false,
			"algorithm": "none",
		}, nil
	}
	algorithm := "none"
	if len(out.ServerSideEncryptionConfiguration.Rules) > 0 {
		rule := out.ServerSideEncryptionConfiguration.Rules[0]
		if rule.ApplyServerSideEncryptionByDefault != nil {
			algorithm = string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
		}
	}
	return map[string]interface{}{
		"enforced":  true,
		"algorithm": algorithm,
	}, nil
}

func SimulateUnencryptedWrite(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult
	
	s3Data, ok := data.(scanner.S3AuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_unencrypted_write expects scanner.S3AuditResults")
	}

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %v", err)
	}

	s3Client := awss3.NewFromConfig(cfg)
	configClient := configservice.NewFromConfig(cfg)

	for _, bucket := range s3Data.Buckets {
		if bucket.Name == nil {
			continue
		}
		fmt.Printf("[Chaos Trigger] Starting SimulateUnencryptedWrite on bucket %s\n", *bucket.Name)
		exp := UnencryptedWrite{
			S3Client:     s3Client,
			ConfigClient: configClient,
			BucketName:   *bucket.Name,
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