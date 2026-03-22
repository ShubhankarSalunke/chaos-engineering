package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	ServerURL string `json:"server_url"`
}

func GetServerURL() string {

	file, err := os.Open(os.Getenv("HOME") + "/.chaos/config.json")
	if err != nil {
		return "http://localhost:8000"
	}
	defer file.Close()

	var cfg Config
	json.NewDecoder(file).Decode(&cfg)

	if cfg.ServerURL == "" {
		return "http://localhost:8000"
	}

	return cfg.ServerURL
}
