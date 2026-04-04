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
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/google/uuid"
)

type EBSUnencryptedAccess struct {
	EC2Client *awsec2.Client
	SSMClient *ssm.Client
	VolumeID  string
}

func (e *EBSUnencryptedAccess) Run() (*auditexperiments.ExperimentResult, error){
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_ebs_unencrypted_access",
		TargetID:     e.VolumeID,
		StartTime:    time.Now(),
		Impact:       "data_exposure",
	}

	volMeta, err := getVolumeMetadata(ctx, e.EC2Client, e.VolumeID)

	if err != nil{
		return nil, fmt.Errorf("could not describe volume: %w", err)
	}

	result.PreSnapshot = volMeta
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail:    fmt.Sprintf("volume %s — encrypted: %v, state: %v, attached: %v", e.VolumeID, volMeta["encrypted"], volMeta["state"], volMeta["attached"]),
	}) 

	if !volMeta["attached"].(bool){
		result.Status = "completed"
		result.Restored = true
		result.PostSnapshot = map[string]interface{}{
			"skipped": true,
			"reason":  "volume not attached to any instance — skipping attack simulation",
		}
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "skipped",
			Detail:    fmt.Sprintf("volume %s is not attached — skipping", e.VolumeID),
		})
		result.EndTime = time.Now()
		return result, nil
	}

	attachedInstanceID := volMeta["attached_instance"].(string)
	az := volMeta["availability_zone"].(string)

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "attack_started",
		Detail:    fmt.Sprintf("volume attached to %s in %s — simulating data access via snapshot clone", attachedInstanceID, az),
	})

	snapOut, err := e.EC2Client.CreateSnapshot(ctx, &awsec2.CreateSnapshotInput{
		VolumeId:    aws.String(e.VolumeID),
		Description: aws.String("chaos-experiment-ebs-access-simulation"),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeSnapshot,
				Tags:         []types.Tag{{Key: aws.String("chaos-experiment"), Value: aws.String("true")}},
			},
		},
	})
	if err != nil {
		result.Status = "failed"
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "snapshot_failed",
			Detail:    fmt.Sprintf("could not snapshot volume: %v", err),
		})
		result.EndTime = time.Now()
		return result, nil
	}

	snapID := *snapOut.SnapshotId
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "snapshot_created",
		Detail:    fmt.Sprintf("snapshot %s created from unencrypted volume", snapID),
	})

	snapWaiter := awsec2.NewSnapshotCompletedWaiter(e.EC2Client)
	if err := snapWaiter.Wait(ctx, &awsec2.DescribeSnapshotsInput{
		SnapshotIds: []string{snapID},
	}, 10*time.Minute); err != nil {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "snapshot_timeout",
			Detail:    "snapshot did not complete in time",
		})
		e.cleanupSnapshot(ctx, snapID, result)
		result.EndTime = time.Now()
		result.Status = "completed"
		return result, nil
	}


	newVolOut, err := e.EC2Client.CreateVolume(ctx, &awsec2.CreateVolumeInput{
		SnapshotId:       aws.String(snapID),
		AvailabilityZone: aws.String(az),
		VolumeType:       types.VolumeTypeGp2,
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeVolume,
				Tags:         []types.Tag{{Key: aws.String("chaos-experiment"), Value: aws.String("true")}},
			},
		},
	})

	if err != nil {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "volume_create_failed",
			Detail:    fmt.Sprintf("could not create volume from snapshot: %v", err),
		})
		e.cleanupSnapshot(ctx, snapID, result)
		result.EndTime = time.Now()
		result.Status = "completed"
		return result, nil
	}

	newVolID := *newVolOut.VolumeId
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "volume_created",
		Detail:    fmt.Sprintf("clone volume %s created in %s", newVolID, az),
	})

	volWaiter := awsec2.NewVolumeAvailableWaiter(e.EC2Client)
	if err := volWaiter.Wait(ctx, &awsec2.DescribeVolumesInput{
		VolumeIds: []string{newVolID},
	}, 5*time.Minute); err != nil {
		e.cleanupVolume(ctx, newVolID, result)
		e.cleanupSnapshot(ctx, snapID, result)
		result.EndTime = time.Now()
		result.Status = "completed"
		return result, nil
	}


	tempDevice := "/dev/xvdz"
	_, err = e.EC2Client.AttachVolume(ctx, &awsec2.AttachVolumeInput{
		VolumeId:   aws.String(newVolID),
		InstanceId: aws.String(attachedInstanceID),
		Device:     aws.String(tempDevice),
	})
	if err != nil {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "attach_failed",
			Detail:    fmt.Sprintf("could not attach clone volume: %v", err),
		})
		e.cleanupVolume(ctx, newVolID, result)
		e.cleanupSnapshot(ctx, snapID, result)
		result.EndTime = time.Now()
		result.Status = "completed"
		return result, nil
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "volume_attached",
		Detail:    fmt.Sprintf("clone volume %s attached to %s at %s", newVolID, attachedInstanceID, tempDevice),
	})
 

	inUseWaiter := awsec2.NewVolumeInUseWaiter(e.EC2Client)
	inUseWaiter.Wait(ctx, &awsec2.DescribeVolumesInput{
		VolumeIds: []string{newVolID},
	}, 3*time.Minute)


	dataRead := false
	if e.checkSSMAvailable(ctx, attachedInstanceID) {
		output, err := e.runSSMCommand(ctx, attachedInstanceID, fmt.Sprintf(
			"sudo dd if=%s bs=512 count=10 2>/dev/null | strings | head -20", tempDevice,
		))
		if err == nil && len(output) > 0 {
			dataRead = true
			result.Observations = append(result.Observations, auditexperiments.ObservationLog{
				Timestamp: time.Now(),
				Event:     "critical_finding",
				Detail:    "CRITICAL: successfully read data from unencrypted volume — plaintext data accessible",
			})
		}
	} else {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "finding",
			Detail:    "clone volume successfully attached — SSM unavailable but physical volume access is confirmed",
		})
	}


	e.EC2Client.DetachVolume(ctx, &awsec2.DetachVolumeInput{
		VolumeId: aws.String(newVolID),
		Force:    aws.Bool(true),
	})
	awsec2.NewVolumeAvailableWaiter(e.EC2Client).Wait(ctx, &awsec2.DescribeVolumesInput{
		VolumeIds: []string{newVolID},
	}, 3*time.Minute)
 
	e.cleanupVolume(ctx, newVolID, result)
	e.cleanupSnapshot(ctx, snapID, result)

	result.PostSnapshot = map[string]interface{}{
		"snapshot_created": snapID,
		"volume_cloned":    newVolID,
		"data_read":        dataRead,
	}
	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = true
	result.EndTime = time.Now()
	result.Status = "completed"
 
	return result, nil
}



func (e *EBSUnencryptedAccess) cleanupSnapshot(ctx context.Context, snapID string, result *auditexperiments.ExperimentResult) {
	_, err := e.EC2Client.DeleteSnapshot(ctx, &awsec2.DeleteSnapshotInput{SnapshotId: aws.String(snapID)})
	event, detail := "snapshot_deleted", fmt.Sprintf("snapshot %s deleted", snapID)
	if err != nil {
		event = "snapshot_delete_failed"
		detail = fmt.Sprintf("could not delete snapshot %s: %v — delete manually", snapID, err)
	}
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(), Event: event, Detail: detail,
	})
}
 
func (e *EBSUnencryptedAccess) cleanupVolume(ctx context.Context, volID string, result *auditexperiments.ExperimentResult) {
	_, err := e.EC2Client.DeleteVolume(ctx, &awsec2.DeleteVolumeInput{VolumeId: aws.String(volID)})
	event, detail := "volume_deleted", fmt.Sprintf("volume %s deleted", volID)
	if err != nil {
		event = "volume_delete_failed"
		detail = fmt.Sprintf("could not delete volume %s: %v — delete manually", volID, err)
	}
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(), Event: event, Detail: detail,
	})
}
 
func (e *EBSUnencryptedAccess) checkSSMAvailable(ctx context.Context, instanceID string) bool {
	out, err := e.SSMClient.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{
		Filters: []ssmtypes.InstanceInformationStringFilter{
			{Key: aws.String("InstanceIds"), Values: []string{instanceID}},
		},
	})
	if err != nil {
		return false
	}
	for _, info := range out.InstanceInformationList {
		if info.PingStatus == ssmtypes.PingStatusOnline {
			return true
		}
	}
	return false
}
 
func (e *EBSUnencryptedAccess) runSSMCommand(ctx context.Context, instanceID, command string) (string, error) {
	sendOut, err := e.SSMClient.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters:   map[string][]string{"commands": {command}},
	})
	if err != nil {
		return "", err
	}
	commandID := *sendOut.Command.CommandId
	for i := 0; i < 12; i++ {
		time.Sleep(5 * time.Second)
		res, err := e.SSMClient.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(commandID),
			InstanceId: aws.String(instanceID),
		})
		if err != nil {
			continue
		}
		if res.Status == ssmtypes.CommandInvocationStatusSuccess {
			return aws.ToString(res.StandardOutputContent), nil
		}
		if res.Status == ssmtypes.CommandInvocationStatusFailed {
			return "", fmt.Errorf("command failed: %s", aws.ToString(res.StandardErrorContent))
		}
	}
	return "", fmt.Errorf("command timed out")
}
 
func getVolumeMetadata(ctx context.Context, client *awsec2.Client, volumeID string) (map[string]interface{}, error) {
	out, err := client.DescribeVolumes(ctx, &awsec2.DescribeVolumesInput{
		VolumeIds: []string{volumeID},
	})
	if err != nil {
		return nil, err
	}
	if len(out.Volumes) == 0 {
		return nil, fmt.Errorf("volume not found")
	}
	v := out.Volumes[0]
	attached := len(v.Attachments) > 0
	attachedInstance, device := "", ""
	if attached {
		attachedInstance = aws.ToString(v.Attachments[0].InstanceId)
		device = aws.ToString(v.Attachments[0].Device)
	}
	return map[string]interface{}{
		"volume_id":         volumeID,
		"encrypted":         aws.ToBool(v.Encrypted),
		"size_gib":          aws.ToInt32(v.Size),
		"state":             string(v.State),
		"attached":          attached,
		"attached_instance": attachedInstance,
		"device":            device,
		"availability_zone": aws.ToString(v.AvailabilityZone),
	}, nil
}

func SimulateEBSUnencryptedAccess(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult
	ec2Data, ok := data.(scanner.Ec2AuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_ebs_unencrypted_access expects scanner.Ec2AuditResults")
	}

	ssmClient := ssm.New(ssm.Options{
		Region:      client.Options().Region,
		Credentials: client.Options().Credentials,
	})

	for _, vol := range ec2Data.Volumes {
		if vol.VolumeId != nil {
			fmt.Printf("[Chaos Trigger] Starting EBS unencrypted access simulation on volume %s\n", *vol.VolumeId)
			exp := EBSUnencryptedAccess{
				EC2Client: client,
				SSMClient: ssmClient,
				VolumeID:  *vol.VolumeId,
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
	}
	return results, nil
}