package ec2

import (
	"context"
	"fmt"
	"strings"
	"time"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/google/uuid"
)

var metadataTargets = []struct{ name, path string }{
	{"iam_credentials_list", "/latest/meta-data/iam/security-credentials/"},
	{"instance_id", "/latest/meta-data/instance-id"},
	{"ami_id", "/latest/meta-data/ami-id"},
	{"hostname", "/latest/meta-data/hostname"},
	{"public_keys", "/latest/meta-data/public-keys/"},
	{"user_data", "/latest/user-data"},
}

type SSRFMetadataTheft struct {
	EC2Client      *awsec2.Client
	SSMClient      *ssm.Client
	InstanceID     string
}

func (e *SSRFMetadataTheft) Run() (*auditexperiments.ExperimentResult, error){
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_ssrf_metadata_theft",
		TargetID:     e.InstanceID,
		StartTime:    time.Now(),
		Impact:       "credential_exposure",
	}

	result.PreSnapshot = map[string]interface{}{
		"instance_id":      e.InstanceID,
		"imdsv2_enforced":  false,
		"metadata_targets": len(metadataTargets),
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail:    fmt.Sprintf("instance %s has IMDSv2 disabled — metadata endpoint accessible via IMDSv1", e.InstanceID),
	})

	ssmAvailable := e.checkSSMAvailable(ctx)
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "ssm_check",
		Detail:    fmt.Sprintf("SSM agent available: %v", ssmAvailable),
	})

		if !ssmAvailable {
		result.Status = "completed"
		result.Restored = true
		result.PostSnapshot = map[string]interface{}{
			"ssm_available":   false,
			"metadata_stolen": false,
			"reason":          "neither chaos agent nor SSM agent reachable on instance — manual verification required",
		}
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "skipped",
			Detail:    "cannot reach instance — IMDSv1 is enabled but attack simulation requires in-instance execution via SSM or chaos agent",
		})
		result.EndTime = time.Now()
		return result, nil
	}


	stolen := make(map[string]string)
	credentialFound := false

	for _, target := range metadataTargets{
		output, err := e.runSSMCommand(ctx, fmt.Sprintf(
			"curl -s http://169.254.169.254%s", target.path,
		))

		if err != nil{
			result.Observations = append(result.Observations, auditexperiments.ObservationLog{
				Timestamp: time.Now(),
				Event:     "fetch_failed",
				Detail:    fmt.Sprintf("%s → error: %v", target.name, err),
			})
			continue
		}

		stolen[target.name] = output
		event := "metadata_stolen"

		if target.name == "iam_credentials_list" && strings.TrimSpace(output) != "" {
			roleName := strings.TrimSpace(output)
			credOutput, err := e.runSSMCommand(ctx, fmt.Sprintf(
				"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", roleName,
			))
			if err == nil {
				stolen["iam_credentials"] = credOutput
				credentialFound = true
				event = "iam_credentials_stolen"
			}
		}


		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     event,
			Detail:    fmt.Sprintf("%s → retrieved %d bytes", target.name, len(output)),
		})

	}
	if credentialFound {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "critical_finding",
			Detail:    "CRITICAL: IAM credentials successfully stolen via IMDSv1 — attacker can assume instance role",
		})
	}
	result.PostSnapshot = map[string]interface{}{
		"ssm_available":      true,
		"metadata_stolen":    true,
		"endpoints_accessed": len(stolen),
		"iam_creds_exposed":  credentialFound,
		"stolen_fields":      keysOf(stolen),
	}
	
	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = true // read-only attack, nothing to restore
	result.EndTime = time.Now()
	result.Status = "completed"

	return result, nil
}


func (e *SSRFMetadataTheft) checkSSMAvailable(ctx context.Context) bool {
	out, err := e.SSMClient.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{
		Filters: []ssmtypes.InstanceInformationStringFilter{
			{
				Key:    aws.String("InstanceIds"),
				Values: []string{e.InstanceID},
			},
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

func (e *SSRFMetadataTheft) runSSMCommand(ctx context.Context, command string) (string, error) {
	sendOut, err := e.SSMClient.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  []string{e.InstanceID},
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
			InstanceId: aws.String(e.InstanceID),
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
 
func keysOf(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func SimulateSSRFMetadataTheft(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult
	ec2Data, ok := data.(scanner.Ec2AuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_ssrf_metadata_theft expects scanner.Ec2AuditResults")
	}

	ssmClient := ssm.New(ssm.Options{
		Region:      client.Options().Region,
		Credentials: client.Options().Credentials,
	})

	for _, inst := range ec2Data.Instances {
		if inst.InstanceId != nil {
			fmt.Printf("[Chaos Trigger] Starting SSRF metadata theft simulation on instance %s\n", *inst.InstanceId)
			exp := SSRFMetadataTheft{
				EC2Client:  client,
				SSMClient:  ssmClient,
				InstanceID: *inst.InstanceId,
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
	return results, nil
}

