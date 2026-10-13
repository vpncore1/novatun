package proxy

import (
	"bytes"
	"errors"
	"fmt"
)

var (
	ErrMalformedSocks5UDP = errors.New("novatun/socks5: malformed socks5 UDP request packet")
	ErrFragmentNotSupported = errors.New("novatun/socks5: UDP fragmentation not supported")
)

// ParseSocks5UDPPacket parses an RFC 1928 SOCKS5 UDP datagram:
//   [RSV: 2B] [FRAG: 1B] [ATYP: 1B] [ADDR: N bytes] [PORT: 2B] [DATA: M bytes]
// Returns the destination target ("host:port") and the data payload.
func ParseSocks5UDPPacket(packet []byte) (target string, payload []byte, err error) {
	if len(packet) < 4 { // minimum: 2B RSV + 1B FRAG + 1B ATYP
		return "", nil, ErrMalformedSocks5UDP
	}

	// RSV must be 0x00 0x00
	if packet[0] != 0x00 || packet[1] != 0x00 {
		return "", nil, ErrMalformedSocks5UDP
	}

	// FRAG: 0x00 indicates standalone datagram
	frag := packet[2]
	if frag != 0x00 {
		return "", nil, ErrFragmentNotSupported
	}

	// The rest begins with ATYP
	reader := bytes.NewReader(packet[3:])
	target, err = DecodeTargetBytes(reader)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrMalformedSocks5UDP, err)
	}

	// Remaining unread bytes in reader are the UDP payload
	headerLen := len(packet[3:]) - reader.Len()
	payloadStart := 3 + headerLen
	payload = packet[payloadStart:]
	return target, payload, nil
}

// EncodeSocks5UDPPacket wraps a UDP payload with RFC 1928 SOCKS5 UDP header:
//   [RSV: 2B (0x00, 0x00)] [FRAG: 1B (0x00)] [ATYP & ADDR & PORT] [DATA: M bytes]
func EncodeSocks5UDPPacket(target string, payload []byte) ([]byte, error) {
	addrHeader, err := EncodeTargetBytes(target)
	if err != nil {
		return nil, err
	}

	totalLen := 3 + len(addrHeader) + len(payload)
	buf := make([]byte, totalLen)
	buf[0] = 0x00
	buf[1] = 0x00
	buf[2] = 0x00 // FRAG 0x00
	copy(buf[3:3+len(addrHeader)], addrHeader)
	copy(buf[3+len(addrHeader):], payload)

	return buf, nil
}
