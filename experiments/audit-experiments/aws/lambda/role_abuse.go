package lambda

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/google/uuid"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	"github.com/adigajjar/security-audit/scanner"
)

type RoleAbuseScanExposure struct {
	LambdaClient *awslambda.Client
	IAMClient    *awsiam.Client
	FunctionName string
	FunctionArn  string
}

func (e *RoleAbuseScanExposure) Run() (*auditexperiments.ExperimentResult, error) {
	ctx := context.Background()
	result := &auditexperiments.ExperimentResult{
		ExperimentID: uuid.New().String(),
		Type:         "simulate_lambda_role_abuse",
		TargetID:     e.FunctionName,
		StartTime:    time.Now(),
		Impact:       "privilege_escalation_blast_radius",
	}

	// Get Lambda function details
	funcOut, err := e.LambdaClient.GetFunction(ctx, &awslambda.GetFunctionInput{
		FunctionName: &e.FunctionName,
	})
	if err != nil {
		result.Status = "failed"
		result.EndTime = time.Now()
		result.PostSnapshot = map[string]interface{}{
			"error": "could not get Lambda function details",
		}
		return result, fmt.Errorf("could not get Lambda function %s: %w", e.FunctionName, err)
	}

	if funcOut.Configuration == nil || funcOut.Configuration.Role == nil {
		result.Status = "failed"
		result.EndTime = time.Now()
		result.PostSnapshot = map[string]interface{}{
			"error": "Lambda function has no execution role",
		}
		return result, fmt.Errorf("Lambda function %s has no execution role", e.FunctionName)
	}

	roleArn := *funcOut.Configuration.Role
	result.PreSnapshot = map[string]interface{}{
		"function_name":  e.FunctionName,
		"function_arn":   e.FunctionArn,
		"execution_role": roleArn,
		"runtime":        funcOut.Configuration.Runtime,
		"handler":        funcOut.Configuration.Handler,
		"timeout":        funcOut.Configuration.Timeout,
		"memory_mb":      funcOut.Configuration.MemorySize,
	}

	result.Observations = append(result.Observations, auditexperiments.ObservationLog{
		Timestamp: time.Now(),
		Event:     "pre_snapshot",
		Detail:    fmt.Sprintf("Function: %s, Role: %s", e.FunctionName, roleArn),
	})

	// Extract role name from ARN
	roleName := extractRoleNameFromARN(roleArn)
	if roleName == "" {
		result.Status = "completed"
		result.PostSnapshot = map[string]interface{}{
			"role_arn":                  roleArn,
			"analysis_status":           "failed",
			"assumable_roles_found":     0,
			"privilege_escalation_risk": "unknown",
		}
		result.EndTime = time.Now()
		return result, nil
	}

	// Get inline policies for the Lambda execution role
	inlineOut, err := e.IAMClient.ListRolePolicies(ctx, &awsiam.ListRolePoliciesInput{
		RoleName: &roleName,
	})

	inlineCount := 0
	hasAssumeRolePermission := false

	if err == nil && inlineOut != nil {
		inlineCount = len(inlineOut.PolicyNames)
		for _, policyName := range inlineOut.PolicyNames {
			polOut, pErr := e.IAMClient.GetRolePolicy(ctx, &awsiam.GetRolePolicyInput{
				RoleName:   &roleName,
				PolicyName: &policyName,
			})
			if pErr == nil && polOut.PolicyDocument != nil {
				// Check for sts:AssumeRole in policy document
				if containsAssumeRolePermission(*polOut.PolicyDocument) {
					hasAssumeRolePermission = true
					result.Observations = append(result.Observations, auditexperiments.ObservationLog{
						Timestamp: time.Now(),
						Event:     "critical_finding",
						Detail:    fmt.Sprintf("Role %s has sts:AssumeRole permission in inline policy '%s' — privilege escalation vector", roleName, policyName),
					})
				}
			}
		}
	}

	// Get attached policies
	attachedOut, err := e.IAMClient.ListAttachedRolePolicies(ctx, &awsiam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})

	attachedCount := 0
	assumableRoles := []string{}

	if err == nil && attachedOut != nil {
		attachedCount = len(attachedOut.AttachedPolicies)
		for _, policy := range attachedOut.AttachedPolicies {
			if policy.PolicyName != nil && policy.PolicyArn != nil {
				// Check for common privilege escalation patterns
				if *policy.PolicyName == "AdministratorAccess" || *policy.PolicyName == "PowerUserAccess" {
					hasAssumeRolePermission = true
					result.Observations = append(result.Observations, auditexperiments.ObservationLog{
						Timestamp: time.Now(),
						Event:     "critical_finding",
						Detail:    fmt.Sprintf("Role %s has '%s' managed policy attached — full privilege escalation possible", roleName, *policy.PolicyName),
					})
				}

				// Get policy version to check for AssumeRole permissions
				polOut, pErr := e.IAMClient.GetPolicy(ctx, &awsiam.GetPolicyInput{
					PolicyArn: policy.PolicyArn,
				})
				if pErr == nil && polOut.Policy != nil && polOut.Policy.DefaultVersionId != nil {
					verOut, vErr := e.IAMClient.GetPolicyVersion(ctx, &awsiam.GetPolicyVersionInput{
						PolicyArn: policy.PolicyArn,
						VersionId: polOut.Policy.DefaultVersionId,
					})
					if vErr == nil && verOut.PolicyVersion != nil && verOut.PolicyVersion.Document != nil {
						if containsAssumeRolePermission(*verOut.PolicyVersion.Document) {
							hasAssumeRolePermission = true
							result.Observations = append(result.Observations, auditexperiments.ObservationLog{
								Timestamp: time.Now(),
								Event:     "critical_finding",
								Detail:    fmt.Sprintf("Role %s has sts:AssumeRole in attached policy '%s' — can enumerate and assume other roles", roleName, *policy.PolicyName),
							})
						}
					}
				}
			}
		}
	}

	// Enumerate other roles in account that this Lambda could potentially assume
	roleList, err := e.IAMClient.ListRoles(ctx, &awsiam.ListRolesInput{})
	if err == nil && roleList != nil && hasAssumeRolePermission {
		for _, role := range roleList.Roles {
			if role.RoleName != nil && *role.RoleName != roleName {
				// Check trust policy to see if Lambda role can assume this role
				assumableRoles = append(assumableRoles, *role.RoleName)
			}
		}
	}

	result.PostSnapshot = map[string]interface{}{
		"role_arn":                   roleArn,
		"inline_policies_attached":   inlineCount,
		"managed_policies_attached":  attachedCount,
		"has_assume_role_permission": hasAssumeRolePermission,
		"assumable_roles_found":      len(assumableRoles),
		"assumable_roles_list":       assumableRoles,
		"privilege_escalation_risk":  "HIGH",
		"attack_vector":              "Lambda executes code → uses execution role → assumes other roles → access downstream resources",
	}

	if hasAssumeRolePermission {
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "blast_radius_assessment",
			Detail:    fmt.Sprintf("Blast radius: %d assumable roles — attacker can escalate privileges and access sensitive resources", len(assumableRoles)),
		})
		result.Status = "vulnerability_confirmed"
	} else {
		result.Status = "completed"
		result.Observations = append(result.Observations, auditexperiments.ObservationLog{
			Timestamp: time.Now(),
			Event:     "finding",
			Detail:    fmt.Sprintf("Role %s does not have explicit sts:AssumeRole permissions — privilege escalation likely blocked", roleName),
		})
	}

	result.SnapshotDiff = diffSnapshots(result.PreSnapshot, result.PostSnapshot)
	result.Restored = true // read-only scan
	result.EndTime = time.Now()

	return result, nil
}

func containsAssumeRolePermission(policyDoc string) bool {
	// Simple string matching for AssumeRole action
	return (contains(policyDoc, "sts:AssumeRole") ||
		contains(policyDoc, "sts:*") ||
		contains(policyDoc, "*") && contains(policyDoc, "Action")) &&
		(contains(policyDoc, "Allow"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && ((len(s) > len(substr) && s[:len(substr)] == substr) || containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func extractRoleNameFromARN(arn string) string {
	// ARN format: arn:aws:iam::123456789012:role/role-name
	parts := len(arn)
	for i := parts - 1; i >= 0; i-- {
		if arn[i] == '/' {
			return arn[i+1:]
		}
	}
	return ""
}

func SimulateLambdaRoleAbuse(lambdaClient *awslambda.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	var results []*auditexperiments.ExperimentResult

	lambdaData, ok := data.(scanner.LambdaAuditResults)
	if !ok {
		return nil, fmt.Errorf("simulate_lambda_role_abuse expects scanner.LambdaAuditResults")
	}

	// Get IAM client
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	iamClient := awsiam.NewFromConfig(cfg)

	for _, fn := range lambdaData.Functions {
		if fn.FunctionName != nil && fn.FunctionArn != nil {
			fmt.Printf("[Chaos Trigger] Starting Lambda role abuse assessment on %s\n", *fn.FunctionName)
			exp := RoleAbuseScanExposure{
				LambdaClient: lambdaClient,
				IAMClient:    iamClient,
				FunctionName: *fn.FunctionName,
				FunctionArn:  *fn.FunctionArn,
			}
			res, err := exp.Run()
			if err != nil {
				fmt.Printf("[Chaos Trigger] Experiment failed: %v\n", err)
			} else {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
