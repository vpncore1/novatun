package config

import (
	"os"
	"path/filepath"
	"testing"

	"novatun/pkg/crypto"
)

func TestServerConfigLoadAndValidate(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	hexKey := fmtHex(key)

	jsonContent := []byte(`{
		"listen": ":443",
		"psk": "` + hexKey + `",
		"mode": "ws",
		"path": "/api/v1/stream",
		"fallback_addr": "127.0.0.1:80",
		"log_level": "info"
	}`)

	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "server.json")
	if err := os.WriteFile(confPath, jsonContent, 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(confPath)
	if err != nil {
		t.Fatalf("LoadServerConfig failed: %v", err)
	}

	if cfg.Listen != ":443" || cfg.Mode != "ws" || cfg.Path != "/api/v1/stream" {
		t.Fatalf("Loaded values mismatch: %+v", cfg)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
}

func TestClientConfigLoadAndValidate(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	hexKey := fmtHex(key)

	jsonContent := []byte(`{
		"server": "198.51.100.1:443",
		"psk": "` + hexKey + `",
		"mode": "ws",
		"host": "legit-domain.com",
		"path": "/api/v1/stream",
		"socks": "127.0.0.1:1080",
		"tun": true,
		"tun_name": "novatun0"
	}`)

	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "client.json")
	if err := os.WriteFile(confPath, jsonContent, 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadClientConfig(confPath)
	if err != nil {
		t.Fatalf("LoadClientConfig failed: %v", err)
	}

	if cfg.Server != "198.51.100.1:443" || !cfg.TUN || cfg.Host != "legit-domain.com" {
		t.Fatalf("Loaded values mismatch: %+v", cfg)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
}

func TestConfigValidationErrors(t *testing.T) {
	// Empty PSK
	srvCfg := ServerConfig{Listen: ":8443"}
	if err := srvCfg.Validate(); err == nil {
		t.Fatal("expected error on empty PSK")
	}

	// Invalid PSK
	srvCfg.PSK = "invalid-hex"
	if err := srvCfg.Validate(); err == nil {
		t.Fatal("expected error on malformed PSK")
	}

	// Client without server or inbound
	cliCfg := ClientConfig{PSK: "0000000000000000000000000000000000000000000000000000000000000001"}
	if err := cliCfg.Validate(); err == nil {
		t.Fatal("expected error on missing server address")
	}

	cliCfg.Server = "1.2.3.4:443"
	// No socks, tun, or forward_ports
	if err := cliCfg.Validate(); err == nil {
		t.Fatal("expected error when no inbound service is specified")
	}

	// Valid with ForwardPorts
	cliCfg.ForwardPorts = "443,80,2053,8000-8005"
	if err := cliCfg.Validate(); err != nil {
		t.Fatalf("expected valid with ForwardPorts, got: %v", err)
	}
}

func TestParsePortList(t *testing.T) {
	ports, err := ParsePortList("443, 80, 2053, 8000-8003")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := map[int]bool{443: true, 80: true, 2053: true, 8000: true, 8001: true, 8002: true, 8003: true}
	if len(ports) != len(expected) {
		t.Fatalf("expected %d ports, got %d (%v)", len(expected), len(ports), ports)
	}
	for _, p := range ports {
		if !expected[p] {
			t.Fatalf("unexpected port %d in result", p)
		}
	}

	// Invalid ports
	if _, err := ParsePortList("invalid"); err == nil {
		t.Fatal("expected error on invalid port")
	}
	if _, err := ParsePortList("70000"); err == nil {
		t.Fatal("expected error on port > 65535")
	}
}

func fmtHex(b []byte) string {
	res := ""
	for _, v := range b {
		res += fmtHexByte(v)
	}
	return res
}

func fmtHexByte(b byte) string {
	const hexChars = "0123456789abcdef"
	return string([]byte{hexChars[b>>4], hexChars[b&0x0f]})
}
