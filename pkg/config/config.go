package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"novatun/pkg/crypto"
)

// ServerConfig defines the configuration parameters for novatun server.
type ServerConfig struct {
	Listen       string `json:"listen"`
	PSK          string `json:"psk"`
	Mode         string `json:"mode"`
	Path         string `json:"path"`
	FallbackAddr string `json:"fallback_addr"`
	LogLevel     string `json:"log_level"`
}

// ClientConfig defines the configuration parameters for novatun client.
type ClientConfig struct {
	Server   string `json:"server"`
	PSK      string `json:"psk"`
	Mode     string `json:"mode"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	Socks    string `json:"socks"`
	TUN      bool   `json:"tun"`
	TUNName  string `json:"tun_name"`
	LogLevel string `json:"log_level"`
}

// DefaultServerConfig returns production defaults for the server.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Listen:       ":8443",
		Mode:         "raw",
		Path:         "/api/v1/stream",
		FallbackAddr: "127.0.0.1:80",
		LogLevel:     "info",
	}
}

// DefaultClientConfig returns production defaults for the client.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Server:   "127.0.0.1:8443",
		Mode:     "raw",
		Path:     "/api/v1/stream",
		Socks:    "127.0.0.1:1080",
		TUN:      false,
		TUNName:  "novatun0",
		LogLevel: "info",
	}
}

// LoadServerConfig reads configuration from path if provided, filling in defaults and validating PSK.
func LoadServerConfig(path string) (*ServerConfig, error) {
	cfg := DefaultServerConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read server config file %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse server config JSON: %w", err)
		}
	}
	return &cfg, nil
}

// Validate checks server configuration consistency.
func (c *ServerConfig) Validate() error {
	if c.Listen == "" {
		return errors.New("server config: listen address cannot be empty")
	}
	if c.PSK == "" {
		return errors.New("server config: PSK cannot be empty")
	}
	if _, err := crypto.ParsePSK(c.PSK); err != nil {
		return fmt.Errorf("server config: invalid PSK: %w", err)
	}
	if c.Mode != "raw" && c.Mode != "ws" {
		c.Mode = "raw"
	}
	return nil
}

// LoadClientConfig reads configuration from path if provided, filling in defaults.
func LoadClientConfig(path string) (*ClientConfig, error) {
	cfg := DefaultClientConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read client config file %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse client config JSON: %w", err)
		}
	}
	return &cfg, nil
}

// Validate checks client configuration consistency.
func (c *ClientConfig) Validate() error {
	if c.Server == "" {
		return errors.New("client config: server address cannot be empty")
	}
	if c.PSK == "" {
		return errors.New("client config: PSK cannot be empty")
	}
	if _, err := crypto.ParsePSK(c.PSK); err != nil {
		return fmt.Errorf("client config: invalid PSK: %w", err)
	}
	if c.Mode != "raw" && c.Mode != "ws" {
		c.Mode = "raw"
	}
	if c.Socks == "" && !c.TUN {
		return errors.New("client config: at least one inbound service must be enabled (socks or tun)")
	}
	return nil
}
