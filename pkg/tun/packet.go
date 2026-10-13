package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// IP protocol numbers
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

var (
	ErrPacketTooShort = errors.New("novatun/tun: packet too short for IP header")
	ErrUnsupportedIP  = errors.New("novatun/tun: unsupported IP version (only IPv4 supported)")
)

// ParsedPacket contains extracted layer 3/4 information from a raw IP datagram.
type ParsedPacket struct {
	Version  int
	Protocol int
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Payload  []byte

	// Header raw bytes for potential NAT / reconstruction
	IPHeader  []byte
	L4Header  []byte
	RawPacket []byte
}

// Target returns the destination endpoint as "dstIP:dstPort".
func (p *ParsedPacket) Target() string {
	return net.JoinHostPort(p.DstIP.String(), fmt.Sprintf("%d", p.DstPort))
}

// Source returns the source endpoint as "srcIP:srcPort".
func (p *ParsedPacket) Source() string {
	return net.JoinHostPort(p.SrcIP.String(), fmt.Sprintf("%d", p.SrcPort))
}

// ParseIPv4 parses an IPv4 packet buffer and extracts 5-tuple and payload.
func ParseIPv4(b []byte) (*ParsedPacket, error) {
	if len(b) < 20 {
		return nil, ErrPacketTooShort
	}

	version := b[0] >> 4
	if version != 4 {
		return nil, ErrUnsupportedIP
	}

	ihl := int(b[0]&0x0F) * 4
	if len(b) < ihl {
		return nil, ErrPacketTooShort
	}

	totalLen := int(binary.BigEndian.Uint16(b[2:4]))
	if totalLen < ihl || totalLen > len(b) {
		totalLen = len(b)
	}

	protocol := int(b[9])
	srcIP := net.IP(b[12:16])
	dstIP := net.IP(b[16:20])

	p := &ParsedPacket{
		Version:   4,
		Protocol:  protocol,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		IPHeader:  b[:ihl],
		RawPacket: b[:totalLen],
	}

	l4Bytes := b[ihl:totalLen]

	switch protocol {
	case ProtoTCP:
		if len(l4Bytes) < 20 {
			return nil, ErrPacketTooShort
		}
		p.SrcPort = binary.BigEndian.Uint16(l4Bytes[0:2])
		p.DstPort = binary.BigEndian.Uint16(l4Bytes[2:4])
		tcpHdrLen := int(l4Bytes[12]>>4) * 4
		if len(l4Bytes) < tcpHdrLen {
			return nil, ErrPacketTooShort
		}
		p.L4Header = l4Bytes[:tcpHdrLen]
		p.Payload = l4Bytes[tcpHdrLen:]

	case ProtoUDP:
		if len(l4Bytes) < 8 {
			return nil, ErrPacketTooShort
		}
		p.SrcPort = binary.BigEndian.Uint16(l4Bytes[0:2])
		p.DstPort = binary.BigEndian.Uint16(l4Bytes[2:4])
		udpLen := int(binary.BigEndian.Uint16(l4Bytes[4:6]))
		if udpLen > len(l4Bytes) {
			udpLen = len(l4Bytes)
		}
		p.L4Header = l4Bytes[:8]
		p.Payload = l4Bytes[8:udpLen]

	case ProtoICMP:
		if len(l4Bytes) < 8 {
			return nil, ErrPacketTooShort
		}
		p.L4Header = l4Bytes[:8]
		p.Payload = l4Bytes[8:]
	}

	return p, nil
}

// BuildIPv4UDP crafts an IPv4+UDP packet to inject back into the TUN interface.
func BuildIPv4UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return nil
	}

	udpTotalLen := 8 + len(payload)
	ipTotalLen := 20 + udpTotalLen

	buf := make([]byte, ipTotalLen)

	// IPv4 Header
	buf[0] = 0x45 // Version 4, IHL 5
	buf[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(buf[2:4], uint16(ipTotalLen))
	binary.BigEndian.PutUint16(buf[4:6], 0) // ID
	binary.BigEndian.PutUint16(buf[6:8], 0) // Flags/Fragment
	buf[8] = 64                            // TTL
	buf[9] = ProtoUDP                      // Protocol 17
	// Checksum at 10..12 computed below
	copy(buf[12:16], src4)
	copy(buf[16:20], dst4)

	// Compute IP Header Checksum
	ipChecksum := checksum(buf[:20])
	binary.BigEndian.PutUint16(buf[10:12], ipChecksum)

	// UDP Header
	binary.BigEndian.PutUint16(buf[20:22], srcPort)
	binary.BigEndian.PutUint16(buf[22:24], dstPort)
	binary.BigEndian.PutUint16(buf[24:26], uint16(udpTotalLen))
	buf[26] = 0 // Checksum optional in IPv4 UDP
	buf[27] = 0
	copy(buf[28:], payload)

	return buf
}

// BuildIPv4ICMPEchoReply crafts an ICMP Echo Reply in response to an Echo Request.
func BuildIPv4ICMPEchoReply(request *ParsedPacket) []byte {
	if request.Protocol != ProtoICMP || len(request.L4Header) < 8 {
		return nil
	}
	// Echo Request has type 8, code 0. Echo Reply has type 0, code 0.
	if request.L4Header[0] != 8 {
		return nil
	}

	icmpPayload := append(request.L4Header[4:8], request.Payload...)
	icmpTotalLen := 4 + len(icmpPayload)
	ipTotalLen := 20 + icmpTotalLen

	buf := make([]byte, ipTotalLen)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(ipTotalLen))
	buf[8] = 64
	buf[9] = ProtoICMP
	copy(buf[12:16], request.DstIP.To4()) // swap src/dst
	copy(buf[16:20], request.SrcIP.To4())
	ipCS := checksum(buf[:20])
	binary.BigEndian.PutUint16(buf[10:12], ipCS)

	// ICMP Type 0, Code 0
	buf[20] = 0
	buf[21] = 0
	copy(buf[24:], icmpPayload)
	icmpCS := checksum(buf[20:])
	binary.BigEndian.PutUint16(buf[22:24], icmpCS)

	return buf
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
