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
	Socks        string `json:"socks"`
	ForwardPorts string `json:"forward_ports"`
	TUN          bool   `json:"tun"`
	TUNName      string `json:"tun_name"`
	LogLevel     string `json:"log_level"`
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
	if c.Socks == "" && !c.TUN && c.ForwardPorts == "" {
		return errors.New("client config: at least one inbound service must be enabled (socks, tun, or forward_ports)")
	}
	return nil
}

// ParsePortList parses a comma-separated list of ports or ranges (e.g. "443,80,2053,8000-8005") into a slice of integers.
func ParsePortList(input string) ([]int, error) {
	if input == "" {
		return nil, nil
	}
	portSet := make(map[int]struct{})
	parts := splitClean(input, ",")
	for _, part := range parts {
		if part == "" {
			continue
		}
		if containsRange(part) {
			rangeParts := splitClean(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			start, err := parsePort(rangeParts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid start port in %q: %w", part, err)
			}
			end, err := parsePort(rangeParts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid end port in %q: %w", part, err)
			}
			if start > end {
				start, end = end, start
			}
			for p := start; p <= end; p++ {
				portSet[p] = struct{}{}
			}
		} else {
			p, err := parsePort(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", part, err)
			}
			portSet[p] = struct{}{}
		}
	}

	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	return ports, nil
}

func parsePort(s string) (int, error) {
	var p int
	_, err := fmt.Sscanf(s, "%d", &p)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535, got %q", s)
	}
	return p, nil
}

func splitClean(s, sep string) []string {
	var res []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || (len(sep) == 1 && s[i] == sep[0]) {
			part := trimSpace(s[start:i])
			if part != "" {
				res = append(res, part)
			}
			start = i + 1
		}
	}
	return res
}

func containsRange(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			return true
		}
	}
	return false
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}
