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

type DBCorruptionExposure struct {
	RDSClient    *rds.Client
	DBInstanceID string
}

func (e *DBCorruptionExposure) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_db_corruption",
		TargetID:     e.DBInstanceID,
		StartTime:    time.Now(),
		Impact:       "extended_recovery_time",
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
	backupRetention := int32(0)
	if dbInstance.BackupRetentionPeriod != nil {
		backupRetention = *dbInstance.BackupRetentionPeriod
	}

	multiAZ := false
	if dbInstance.MultiAZ != nil {
		multiAZ = *dbInstance.MultiAZ
	}

	result.PreSnapshot = map[string]interface{}{
		"db_instance_id":   e.DBInstanceID,
		"backup_retention": int(backupRetention),
		"multi_az":         multiAZ,
		"pitr_available":   backupRetention > 0,
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail: fmt.Sprintf("DB: %s, Backups: %d day(s), Multi-AZ: %v",
			e.DBInstanceID, backupRetention, multiAZ),
	})

	// Analyze backup/recovery implications
	if backupRetention == 0 {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "critical_finding",
			Detail:    "CRITICAL: No backup retention — any data loss is PERMANENT, no point-in-time recovery possible",
		})
		result.PostSnapshot = map[string]interface{}{
			"backup_enabled":      false,
			"data_loss_risk":      "TOTAL",
			"rto_estimate":        "Unknown - manual recovery only",
			"rpo_estimate":        "All data since last manual snapshot",
			"recovery_complexity": "CRITICAL",
		}
	} else if backupRetention < 7 {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "finding",
			Detail: fmt.Sprintf("Low backup retention (%d days) — insufficient for most RTO/RPO requirements",
				backupRetention),
		})
		result.PostSnapshot = map[string]interface{}{
			"backup_enabled":      true,
			"data_loss_risk":      fmt.Sprintf("Up to %d days", backupRetention),
			"rto_estimate":        fmt.Sprintf("PITR within %d days", backupRetention),
			"rpo_estimate":        "5 minutes (RDS backup window)",
			"recovery_complexity": "MEDIUM",
			"recommendation":      "Increase to >= 7 days for production",
		}
	} else {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "compliant",
			Detail: fmt.Sprintf("Adequate backup retention (%d days) for acceptable RTO/RPO",
				backupRetention),
		})
		result.PostSnapshot = map[string]interface{}{
			"backup_enabled":      true,
			"data_loss_risk":      "LOW",
			"rto_estimate":        fmt.Sprintf("PITR within %d days", backupRetention),
			"rpo_estimate":        "5 minutes",
			"recovery_complexity": "LOW",
		}
	}

	// Multi-AZ impact analysis
	if !multiAZ {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "az_failure_risk",
			Detail:    "Single-AZ only — AZ failure = complete outage, manual recovery required from backup",
		})
		result.PostSnapshot["az_failure_impact"] = "CRITICAL - manual recovery"
		result.PostSnapshot["failover_time"] = "> 1 hour"
	} else {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "az_resilience_ok",
			Detail:    "Multi-AZ enabled — automatic failover in 30-120 seconds, data loss: NONE",
		})
		result.PostSnapshot["az_failure_impact"] = "NONE - automatic failover"
		result.PostSnapshot["failover_time"] = "30-120 seconds"
	}

	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = true
	result.EndTime = time.Now()
	result.Status = "completed"
	return result, nil
}

func SimulateDBCorruption(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult
	rdsData, ok := data.(scanner.RdsAuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_db_corruption expects scanner.RdsAuditResults")
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

		fmt.Printf("[Chaos Trigger] Starting DB corruption simulation on instance %s\n", *db.DBInstanceIdentifier)

		exp := DBCorruptionExposure{
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
