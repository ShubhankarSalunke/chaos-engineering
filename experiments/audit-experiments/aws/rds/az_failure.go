package rds

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/google/uuid"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
)

type AZFailureSimulation struct {
	RDSClient    *rds.Client
	DBInstanceID string
}

func (e *AZFailureSimulation) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_az_failure",
		TargetID:     e.DBInstanceID,
		StartTime:    time.Now(),
		Impact:       "service_downtime",
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
	multiAZ := false
	if dbInstance.MultiAZ != nil {
		multiAZ = *dbInstance.MultiAZ
	}

	az := ""
	if dbInstance.AvailabilityZone != nil {
		az = *dbInstance.AvailabilityZone
	}

	result.PreSnapshot = map[string]interface{}{
		"db_instance_id":       e.DBInstanceID,
		"availability_zone":    az,
		"multi_az_enabled":     multiAZ,
		"failure_scenario":     "AZ-level network outage",
		"simulated_start_time": time.Now().Unix(),
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail: fmt.Sprintf("DB: %s, AZ: %s, Multi-AZ: %v — simulating AZ failure",
			e.DBInstanceID, az, multiAZ),
	})

	if multiAZ {
		// Multi-AZ database - automatic failover expected
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "automatic_failover_expected",
			Detail:    "Multi-AZ enabled — RDS will automatically fail over to standby replica",
		})

		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "failover_timing",
			Detail:    "Expected failover time: 30-120 seconds, Data loss: NONE",
		})

		result.PostSnapshot = map[string]interface{}{
			"az_failure_status":     "resilient",
			"expected_restore_time": "30-120 seconds",
			"data_loss":             "None (fully replicated)",
			"applications_affected": "Brief interruption during failover",
			"automatic_recovery":    true,
			"sla_impact":            "Minimal",
		}

		result.Status = "completed"
	} else {
		// Single-AZ database - manual recovery required
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "critical_finding",
			Detail:    "Single-AZ only — AZ failure requires MANUAL intervention and database restore",
		})

		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "manual_recovery_required",
			Detail:    "Recovery procedure: 1. Restore from snapshot, 2. Rebuild connections, 3. Update DNS/routing (ETA: >1 hour)",
		})

		result.PostSnapshot = map[string]interface{}{
			"az_failure_status":     "critical",
			"expected_restore_time": ">1 hour (manual intervention required)",
			"data_loss":             "None (if recent snapshot available)",
			"applications_affected": "Complete outage",
			"automatic_recovery":    false,
			"sla_impact":            "VIOLATES most uptime SLAs",
			"recommendation":        "Enable Multi-AZ for production databases immediately",
		}

		result.Status = "vulnerability_confirmed"
	}

	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = true
	result.EndTime = time.Now()
	return result, nil
}

func SimulateAZFailure(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult
	rdsData, ok := data.(scanner.RdsAuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_az_failure expects scanner.RdsAuditResults")
	}

	// Create RDS client with region from EC2 client
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(client.Options().Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	for _, db := range rdsData.DBInstances {
		if db.DBInstanceIdentifier == nil {
			continue
		}

		fmt.Printf("[Chaos Trigger] Starting AZ failure simulation on instance %s\n", *db.DBInstanceIdentifier)

		exp := AZFailureSimulation{
			RDSClient:    rdsClient,
			DBInstanceID: *db.DBInstanceIdentifier,
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
