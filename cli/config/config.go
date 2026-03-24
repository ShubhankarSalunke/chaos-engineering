package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	Token     string `json:"token"`
	ServerURL string `json:"base_url"`
}

func getConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".lucifer", "config.json")
}

func LoadConfig() Config {

	path := getConfigPath()

	file, err := os.ReadFile(path)
	if err != nil {
		return Config{}
	}

	var cfg Config
	json.Unmarshal(file, &cfg)

	return cfg
}

func SaveConfig(cfg Config) error {

	path := getConfigPath()

	// ensure directory exists
	os.MkdirAll(filepath.Dir(path), os.ModePerm)

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func GetServerURL() string {
	var cfg Config
	cfg.ServerURL = "http://localhost:8000"
	// cfg.ServerURL = "https://aws_gateway_link"
	return cfg.ServerURL
}

func GetToken() string {
	return os.Getenv("CHAOS_TOKEN")
}
