package ec2

import "fmt"

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