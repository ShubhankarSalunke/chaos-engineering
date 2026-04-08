package ec2

import (
	"context"
	"fmt"
	"time"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/uuid"
)

type PublicSnapshotScrape struct {
	EC2Client *awsec2.Client
	SnapshotID string
}

func (s *PublicSnapshotScrape) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_public_snapshot_scrape",
		TargetID:     s.SnapshotID,
		StartTime:    time.Now(),
		Impact:       "data_exposure",
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "attack_started",
		Detail:    fmt.Sprintf("simulating scraping of public snapshot %s", s.SnapshotID),
	})

	newVolOut, err := s.EC2Client.CreateVolume(ctx, &awsec2.CreateVolumeInput{
		SnapshotId:       aws.String(s.SnapshotID),
		AvailabilityZone: aws.String("us-east-1a"),
		VolumeType:       types.VolumeTypeGp2,
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeVolume,
				Tags:         []types.Tag{{Key: aws.String("chaos-experiment"), Value: aws.String("true")}},
			},
		},
	})

	if err != nil {
		result.Status = "failed"
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "volume_create_failed",
			Detail:    fmt.Sprintf("could not create volume from public snapshot: %v", err),
		})
		result.EndTime = time.Now()
		return result, nil
	}

	newVolID := *newVolOut.VolumeId
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "volume_created",
		Detail:    fmt.Sprintf("clone volume %s created from public snapshot", newVolID),
	})

	volWaiter := awsec2.NewVolumeAvailableWaiter(s.EC2Client)
	if err := volWaiter.Wait(ctx, &awsec2.DescribeVolumesInput{
		VolumeIds: []string{newVolID},
	}, 5*time.Minute); err != nil {
		s.cleanupVolume(ctx, newVolID, result)
		result.EndTime = time.Now()
		result.Status = "completed"
		return result, nil
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "critical_finding",
		Detail:    "CRITICAL: successfully cloned public snapshot into a new volume - data exfiltration possible",
	})

	s.cleanupVolume(ctx, newVolID, result)

	result.PostSnapshot = map[string]interface{}{
		"volume_cloned": newVolID,
		"data_read":     true,
	}
	result.Restored = true
	result.EndTime = time.Now()
	result.Status = "completed"

	return result, nil
}

func (s *PublicSnapshotScrape) cleanupVolume(ctx context.Context, volID string, result *auditexperiments.ExperimentResult) {
	_, err := s.EC2Client.DeleteVolume(ctx, &awsec2.DeleteVolumeInput{VolumeId: aws.String(volID)})
	event, detail := "volume_deleted", fmt.Sprintf("volume %s deleted", volID)
	if err != nil {
		event = "volume_delete_failed"
		detail = fmt.Sprintf("could not delete volume %s: %v — delete manually", volID, err)
	}
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(), Event: event, Detail: detail,
	})
}

func SimulatePublicSnapshotScrape(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult
	ec2Data, ok := data.(scanner.Ec2AuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_public_snapshot_scrape expects scanner.Ec2AuditResults")
	}

	for _, snapID := range ec2Data.PublicSnapshots {
		fmt.Printf("[Chaos Trigger] Starting public snapshot scrape simulation on snapshot %s\n", snapID)
		exp := PublicSnapshotScrape{
			EC2Client: client,
			SnapshotID: snapID,
		}
		res, err := exp.Run()
		if err != nil {
			fmt.Printf("[Chaos Trigger] Experiment failed: %v\n", err)
		} else {
			fmt.Printf("[Chaos Trigger] Experiment completed: Impact=%s, Status=%s\n", res.Impact, res.Status)
			if res != nil {
				results = append(results, res)
			}
		}
	}
	return results, nil
}
