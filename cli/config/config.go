package config

type Config struct {
	ServerURL string `json:"server_url"`
}

func GetServerURL() string {
	var cfg Config
	cfg.ServerURL = "http://localhost:8000"
	// cfg.ServerURL = "https://aws_gateway_link"
	return cfg.ServerURL
}
