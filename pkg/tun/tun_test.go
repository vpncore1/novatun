package tun

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestParseIPv4Packet(t *testing.T) {
	// Construct a synthetic IPv4 UDP packet
	srcIP := net.ParseIP("192.168.1.50").To4()
	dstIP := net.ParseIP("8.8.8.8").To4()
	srcPort := uint16(53412)
	dstPort := uint16(53)
	payload := []byte("synthetic DNS query")

	rawPacket := BuildIPv4UDP(srcIP, dstIP, srcPort, dstPort, payload)
	if rawPacket == nil {
		t.Fatal("BuildIPv4UDP failed to craft packet")
	}

	parsed, err := ParseIPv4(rawPacket)
	if err != nil {
		t.Fatalf("ParseIPv4 failed: %v", err)
	}

	if parsed.Version != 4 {
		t.Errorf("Expected version 4, got %d", parsed.Version)
	}
	if parsed.Protocol != ProtoUDP {
		t.Errorf("Expected protocol UDP (17), got %d", parsed.Protocol)
	}
	if !parsed.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP mismatch: got %s, want %s", parsed.SrcIP, srcIP)
	}
	if !parsed.DstIP.Equal(dstIP) {
		t.Errorf("DstIP mismatch: got %s, want %s", parsed.DstIP, dstIP)
	}
	if parsed.SrcPort != srcPort {
		t.Errorf("SrcPort mismatch: got %d, want %d", parsed.SrcPort, srcPort)
	}
	if parsed.DstPort != dstPort {
		t.Errorf("DstPort mismatch: got %d, want %d", parsed.DstPort, dstPort)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Errorf("Payload mismatch: got %q, want %q", parsed.Payload, payload)
	}

	if parsed.Target() != "8.8.8.8:53" {
		t.Errorf("Target mismatch: got %s, want 8.8.8.8:53", parsed.Target())
	}
	if parsed.Source() != "192.168.1.50:53412" {
		t.Errorf("Source mismatch: got %s, want 192.168.1.50:53412", parsed.Source())
	}
}

func TestICMPEchoReplyCrafting(t *testing.T) {
	// Construct an ICMP Echo Request (Ping)
	ipTotalLen := 20 + 8 + 4 // IP (20) + ICMP Header (8) + Payload (4)
	buf := make([]byte, ipTotalLen)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(ipTotalLen))
	buf[9] = ProtoICMP
	copy(buf[12:16], net.ParseIP("10.255.0.2").To4())
	copy(buf[16:20], net.ParseIP("10.255.0.1").To4())

	// ICMP Echo Request: Type 8, Code 0
	buf[20] = 8
	buf[21] = 0
	buf[22] = 0 // Checksum placeholder
	buf[23] = 0
	buf[24] = 0x12 // ID
	buf[25] = 0x34
	buf[26] = 0x00 // Sequence
	buf[27] = 0x01
	copy(buf[28:], []byte("PING"))

	parsed, err := ParseIPv4(buf)
	if err != nil {
		t.Fatalf("ParseIPv4 on ICMP failed: %v", err)
	}

	reply := BuildIPv4ICMPEchoReply(parsed)
	if reply == nil {
		t.Fatal("BuildIPv4ICMPEchoReply returned nil")
	}

	parsedReply, err := ParseIPv4(reply)
	if err != nil {
		t.Fatalf("ParseIPv4 on reply failed: %v", err)
	}

	// Echo Reply has Type 0, Code 0
	if parsedReply.L4Header[0] != 0 || parsedReply.L4Header[1] != 0 {
		t.Fatalf("Expected ICMP Echo Reply (Type 0, Code 0), got: Type %d, Code %d",
			parsedReply.L4Header[0], parsedReply.L4Header[1])
	}
	// Source and destination should be swapped
	if !parsedReply.SrcIP.Equal(net.ParseIP("10.255.0.1")) {
		t.Errorf("Reply SrcIP mismatch: got %s, want 10.255.0.1", parsedReply.SrcIP)
	}
	if !parsedReply.DstIP.Equal(net.ParseIP("10.255.0.2")) {
		t.Errorf("Reply DstIP mismatch: got %s, want 10.255.0.2", parsedReply.DstIP)
	}
}

func TestRoutingManagerConstruction(t *testing.T) {
	router := NewRouter("203.0.113.1:8443", "10.255.0.1", "novatun0")
	if router == nil {
		t.Fatal("NewRouter returned nil")
	}
	if router.serverEndpoint != "203.0.113.1:8443" {
		t.Errorf("Server endpoint mismatch: %s", router.serverEndpoint)
	}
	if router.gatewayIP != "10.255.0.1" {
		t.Errorf("Gateway IP mismatch: %s", router.gatewayIP)
	}
}
