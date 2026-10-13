package proxy

import (
	"bytes"
	"net"
	"testing"
)

func TestTargetAddressingProtocol(t *testing.T) {
	testCases := []struct {
		name   string
		target string
	}{
		{"IPv4", "192.168.1.1:8080"},
		{"IPv4_Local", "127.0.0.1:443"},
		{"Domain_Simple", "example.com:80"},
		{"Domain_Subdomain", "api.v1.internal.novatun.org:9443"},
		{"IPv6_Local", "[::1]:53"},
		{"IPv6_Full", "[2001:db8::ff00:42:8329]:8080"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteTarget(&buf, tc.target); err != nil {
				t.Fatalf("WriteTarget failed: %v", err)
			}

			readBack, err := ReadTarget(&buf)
			if err != nil {
				t.Fatalf("ReadTarget failed: %v", err)
			}

			// Normalize host:port for IPv6 brackets comparison
			h1, p1, _ := net.SplitHostPort(tc.target)
			h2, p2, _ := net.SplitHostPort(readBack)

			if net.ParseIP(h1) != nil && net.ParseIP(h2) != nil {
				ip1 := net.ParseIP(h1)
				ip2 := net.ParseIP(h2)
				if !ip1.Equal(ip2) || p1 != p2 {
					t.Fatalf("IP mismatch: got %s, want %s", readBack, tc.target)
				}
			} else {
				if h1 != h2 || p1 != p2 {
					t.Fatalf("Target mismatch: got %s, want %s", readBack, tc.target)
				}
			}
		})
	}
}

func TestMalformedTargets(t *testing.T) {
	var buf bytes.Buffer
	// Invalid target strings
	if err := WriteTarget(&buf, "invalid-no-port"); err == nil {
		t.Fatal("expected error for target without port")
	}
	if err := WriteTarget(&buf, "example.com:9999999"); err == nil {
		t.Fatal("expected error for invalid port range")
	}

	// Invalid address types on read
	badTypeBuf := bytes.NewReader([]byte{0x99, 0x01})
	if _, err := ReadTarget(badTypeBuf); err == nil {
		t.Fatal("expected error on invalid ATYP byte")
	}
}

func TestUDPPacketFraming(t *testing.T) {
	testCases := []struct {
		name    string
		target  string
		payload []byte
	}{
		{"IPv4_Small", "8.8.8.8:53", []byte("dns-query-data")},
		{"Domain_Echo", "echo.novatun.internal:9999", []byte("hello udp voice and gaming")},
		{"IPv6_Payload", "[2001:4860:4860::8888]:53", bytes.Repeat([]byte("X"), 1400)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteUDPPacket(&buf, tc.target, tc.payload); err != nil {
				t.Fatalf("WriteUDPPacket failed: %v", err)
			}

			readTarget, readPayload, err := ReadUDPPacket(&buf)
			if err != nil {
				t.Fatalf("ReadUDPPacket failed: %v", err)
			}

			h1, p1, _ := net.SplitHostPort(tc.target)
			h2, p2, _ := net.SplitHostPort(readTarget)

			if net.ParseIP(h1) != nil && net.ParseIP(h2) != nil {
				ip1 := net.ParseIP(h1)
				ip2 := net.ParseIP(h2)
				if !ip1.Equal(ip2) || p1 != p2 {
					t.Fatalf("Target mismatch: got %s, want %s", readTarget, tc.target)
				}
			} else {
				if h1 != h2 || p1 != p2 {
					t.Fatalf("Target mismatch: got %s, want %s", readTarget, tc.target)
				}
			}

			if !bytes.Equal(readPayload, tc.payload) {
				t.Fatalf("Payload mismatch: got %d bytes, want %d bytes", len(readPayload), len(tc.payload))
			}
		})
	}
}

func TestSocks5UDPPacketEncoding(t *testing.T) {
	target := "1.1.1.1:53"
	payload := []byte("dns query packet")

	encoded, err := EncodeSocks5UDPPacket(target, payload)
	if err != nil {
		t.Fatalf("EncodeSocks5UDPPacket failed: %v", err)
	}

	parsedTarget, parsedPayload, err := ParseSocks5UDPPacket(encoded)
	if err != nil {
		t.Fatalf("ParseSocks5UDPPacket failed: %v", err)
	}

	if parsedTarget != target {
		t.Fatalf("Target mismatch: got %s, want %s", parsedTarget, target)
	}
	if !bytes.Equal(parsedPayload, payload) {
		t.Fatalf("Payload mismatch: got %q, want %q", parsedPayload, payload)
	}
}

