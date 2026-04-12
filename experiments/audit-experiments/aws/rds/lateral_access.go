package rds

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/google/uuid"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
)

type LateralAccessExposure struct {
	EC2Client    *awsec2.Client
	RDSClient    *rds.Client
	DBInstanceID string
	VPCID        string
}

func (e *LateralAccessExposure) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_internal_lateral_db_access",
		TargetID:     e.DBInstanceID,
		StartTime:    time.Now(),
		Impact:       "unauthorized_internal_access",
	}

	// Get DB instance details
	dbOut, err := e.RDSClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: &e.DBInstanceID,
	})
	if err != nil || len(dbOut.DBInstances) == 0 {
		result.Status = "failed"
		result.EndTime = time.Now()
		result.PostSnapshot = map[string]interface{}{
			"error": "could not describe DB instance",
		}
		return result, fmt.Errorf("could not describe DB instance %s: %w", e.DBInstanceID, err)
	}

	dbInstance := dbOut.DBInstances[0]

	// Get DB security groups
	var dbSecurityGroups []string
	if dbInstance.VpcSecurityGroups != nil {
		for _, vpcSG := range dbInstance.VpcSecurityGroups {
			if vpcSG.VpcSecurityGroupId != nil {
				dbSecurityGroups = append(dbSecurityGroups, *vpcSG.VpcSecurityGroupId)
			}
		}
	}

	result.PreSnapshot = map[string]interface{}{
		"db_instance_id":     e.DBInstanceID,
		"vpc_id":             e.VPCID,
		"db_security_groups": dbSecurityGroups,
		"in_vpc":             true,
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail: fmt.Sprintf("DB: %s in VPC: %s with SGs: %v",
			e.DBInstanceID, e.VPCID, dbSecurityGroups),
	})

	// Query EC2 instances in same VPC
	ec2Out, err := e.EC2Client.DescribeInstances(ctx, &awsec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []string{e.VPCID},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	})

	lateralAccessible := false
	exploitableInstanceCount := 0
	var exploitableInstances []string

	if err == nil && ec2Out != nil {
		for _, reservation := range ec2Out.Reservations {
			for _, instance := range reservation.Instances {
				if instance.InstanceId == nil {
					continue
				}

				instanceID := *instance.InstanceId
				exploitableInstanceCount++
				exploitableInstances = append(exploitableInstances, instanceID)

				result.Observations = append(result.Observations, auditexperiments.ObservationLog{
					Timestamp: time.Now(),
					Event:     "lateral_attack_vector",
					Detail:    fmt.Sprintf("Found EC2 instance %s in same VPC — can attempt DB connection", instanceID),
				})

				// Check if there's a security group allowing DB port from this instance
				for _, sg := range instance.SecurityGroups {
					if sg.GroupId != nil {
						for _, dbSG := range dbSecurityGroups {
							if *sg.GroupId == dbSG {
								lateralAccessible = true
								result.Observations = append(result.Observations, auditexperiments.ObservationLog{
									Timestamp: time.Now(),
									Event:     "critical_finding",
									Detail:    fmt.Sprintf("Instance %s shares DB security group %s — direct database access possible", instanceID, dbSG),
								})
								break
							}
						}
					}
				}
			}
		}
	}

	if exploitableInstanceCount > 0 && !lateralAccessible {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "segmentation_gap",
			Detail: fmt.Sprintf("Found %d EC2 instances in same VPC — segmentation weak, lateral access likely possible",
				exploitableInstanceCount),
		})
		lateralAccessible = true
	}

	result.PostSnapshot = map[string]interface{}{
		"ec2_instances_in_vpc":    exploitableInstanceCount,
		"exploitable_instances":   exploitableInstances,
		"lateral_access_possible": lateralAccessible,
		"segmentation_gaps":       exploitableInstanceCount > 0,
		"attack_path":             "Compromise EC2 → Connect to RDS via internal network",
	}

	if lateralAccessible {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "vulnerability_confirmed",
			Detail:    "East-west segmentation insufficient — database accessible from multiple EC2 instances in VPC",
		})
		result.Status = "vulnerability_confirmed"
	} else {
		result.Status = "completed"
	}

	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = true
	result.EndTime = time.Now()
	return result, nil
}

func SimulateInternalLateralDBAccess(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult
	rdsData, ok := data.(scanner.RdsAuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_internal_lateral_db_access expects scanner.RdsAuditResults")
	}

	// Create RDS client with region from EC2 client
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(client.Options().Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	for _, db := range rdsData.DBInstances {
		if db.DBInstanceIdentifier == nil || db.DBSubnetGroup == nil || db.DBSubnetGroup.VpcId == nil {
			continue
		}

		vpcID := *db.DBSubnetGroup.VpcId
		fmt.Printf("[Chaos Trigger] Starting lateral access simulation on instance %s (VPC: %s)\n",
			*db.DBInstanceIdentifier, vpcID)

		exp := LateralAccessExposure{
			EC2Client:    client,
			RDSClient:    rdsClient,
			DBInstanceID: *db.DBInstanceIdentifier,
			VPCID:        vpcID,
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
