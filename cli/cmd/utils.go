package cmd

import (
	"bytes"
	"net/http"

	"github.com/ShubhankarSalunke/chaos-engineering.git/cli/config"
)

func doRequest(method, url string, body []byte) (*http.Response, error) {

	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	token := config.GetToken()

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	return client.Do(req)
}
