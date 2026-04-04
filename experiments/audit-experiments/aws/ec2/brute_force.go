package ec2

import (
	"context"
	"fmt"
	"net"
	"time"

	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
)

var commonCredentials = []struct{ user, pass string }{
	{"root", "root"},
	{"root", "password"},
	{"root", "123456"},
	{"admin", "admin"},
	{"admin", "password"},
	{"ubuntu", "ubuntu"},
	{"ec2-user", "ec2-user"},
	{"root", "toor"},
	{"user", "user"},
	{"root", ""},
}

type BruteForceExposure struct {
	Client          *awsec2.Client
	SecurityGroupID string 
	InstanceID      string 
}

func (e *BruteForceExposure) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_brute_force_exposure",
		TargetID:     e.InstanceID,
		StartTime:    time.Now(),
		Impact:       "remote_access_exposure",
	}

	// Pre snapshot — get public IP of the instance
	ip, err := getInstancePublicIP(ctx, e.Client, e.InstanceID)
	if err != nil {
		return nil, fmt.Errorf("could not get instance public IP: %w", err)
	}
	if ip == "" {
		return nil, fmt.Errorf("instance %s has no public IP — cannot simulate brute force", e.InstanceID)
	}

	result.PreSnapshot = map[string]interface{}{
		"instance_id":      e.InstanceID,
		"public_ip":        ip,
		"security_group":   e.SecurityGroupID,
		"port":             22,
		"attempts_planned": len(commonCredentials),
	}
	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail:    fmt.Sprintf("target: %s (%s), attempting %d credential pairs", e.InstanceID, ip, len(commonCredentials)),
	})

	// Check port is reachable before attempting
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", ip), 5*time.Second)
	if err != nil {
		result.Status = "failed"
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "port_unreachable",
			Detail:    fmt.Sprintf("port 22 not reachable on %s: %v", ip, err),
		})
		result.PostSnapshot = map[string]interface{}{"port_open": false}
		result.EndTime = time.Now()
		return result, nil
	}
	conn.Close()

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "port_confirmed_open",
		Detail:    fmt.Sprintf("port 22 is open on %s — proceeding with brute force", ip),
	})

	// Brute force — attempt each credential pair
	successCount := 0
	failCount := 0
	var successfulCreds []string

	fmt.Printf("[Chaos: Brute Force] Starting attack on %s (%s)...\n", e.InstanceID, ip)
	for i, cred := range commonCredentials {
		fmt.Printf("[Chaos: Brute Force] [%d/%d] Attempting %s:%s... ", i+1, len(commonCredentials), cred.user, cred.pass)
		success, detail := attemptSSH(ip, cred.user, cred.pass)
		event := "attempt_failed"
		if success {
			fmt.Println("✅ SUCCESS!")
			event = "attempt_succeeded"
			successCount++
			successfulCreds = append(successfulCreds, fmt.Sprintf("%s:%s", cred.user, cred.pass))
		} else {
			fmt.Println("❌ Failed")
			event = "attempt_succeeded" // Keeping existing logic but fixing the event name if it was a typo, actually the user had event = "attempt_failed" which is correct for else. Wait, checking original code.
			event = "attempt_failed"
			failCount++
		}
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     event,
			Detail:    detail,
		})
	}

	fmt.Printf("[Chaos: Brute Force] Attack finished. Successes: %d, Failures: %d\n", successCount, failCount)

	// Post snapshot
	result.PostSnapshot = map[string]interface{}{
		"port_open":         true,
		"attempts_made":     len(commonCredentials),
		"successful_logins": successCount,
		"failed_logins":     failCount,
		"successful_creds":  successfulCreds,
	}
	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = true // brute force leaves no state to restore
	result.EndTime = time.Now()
	result.Status = "completed"

	if successCount > 0 {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "critical_finding",
			Detail:    fmt.Sprintf("CRITICAL: %d successful login(s) with common credentials — instance fully compromised", successCount),
		})
	} else {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "finding",
			Detail:    "port 22 is exposed to internet but common credentials failed — key-based auth likely enforced",
		})
	}

	return result, nil
}

func attemptSSH(ip, user, pass string) (bool, string) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", ip), config)
	if err != nil {
		return false, fmt.Sprintf("user=%s pass=%s → failed (%v)", user, pass, err)
	}
	client.Close()
	return true, fmt.Sprintf("user=%s pass=%s → SUCCESS — authenticated", user, pass)
}

func getInstancePublicIP(ctx context.Context, client *awsec2.Client, instanceID string) (string, error) {
	out, err := client.DescribeInstances(ctx, &awsec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return "", err
	}
	for _, r := range out.Reservations {
		for _, i := range r.Instances {
			if i.PublicIpAddress != nil {
				return *i.PublicIpAddress, nil
			}
		}
	}
	return "", nil
}

func SimulateBruteForceExposure(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult
	ec2Data, ok := data.(scanner.Ec2AuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_brute_force_exposure expects scanner.Ec2AuditResults")
	}

	for _, inst := range ec2Data.Instances {
		if len(inst.SecurityGroups) > 0 && inst.InstanceId != nil {
			sgID := *inst.SecurityGroups[0].GroupId
			fmt.Printf("[Chaos Trigger] Starting brute force exposure on instance %s (SG: %s)\n", *inst.InstanceId, sgID)
			exp := BruteForceExposure{
				Client:          client,
				SecurityGroupID: sgID,
				InstanceID:      *inst.InstanceId,
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