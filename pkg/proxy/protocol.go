package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 / Logical Stream Address Types
const (
	AtypIPv4   byte = 0x01
	AtypDomain byte = 0x03
	AtypIPv6   byte = 0x04
)

// StreamType constants to distinguish TCP from UDP logical streams over yamux.
const (
	StreamTypeTCP byte = 0x01
	StreamTypeUDP byte = 0x02
)

var (
	ErrInvalidAddressType = errors.New("novatun/proxy: invalid address type")
	ErrMalformedTarget    = errors.New("novatun/proxy: malformed target specification")
	ErrDomainTooLong      = errors.New("novatun/proxy: domain name exceeds 255 bytes")
	ErrPacketTooLarge     = errors.New("novatun/proxy: UDP packet length exceeds 65535 bytes")
)

// EncodeTargetBytes serializes a target address ("host:port") into the binary addressing wire format:
//   - IPv4:   [0x01] [4B IP] [2B Port BigEndian]
//   - Domain: [0x03] [1B Len] [N bytes Domain] [2B Port BigEndian]
//   - IPv6:   [0x04] [16B IP] [2B Port BigEndian]
func EncodeTargetBytes(target string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedTarget, err)
	}

	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("%w: invalid port %q", ErrMalformedTarget, portStr)
	}
	port := uint16(portNum)

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf := make([]byte, 1+net.IPv4len+2)
			buf[0] = AtypIPv4
			copy(buf[1:1+net.IPv4len], ip4)
			copy(buf[1+net.IPv4len:], portBuf[:])
			return buf, nil
		}
		buf := make([]byte, 1+net.IPv6len+2)
		buf[0] = AtypIPv6
		copy(buf[1:1+net.IPv6len], ip.To16())
		copy(buf[1+net.IPv6len:], portBuf[:])
		return buf, nil
	}

	if len(host) > 255 {
		return nil, ErrDomainTooLong
	}
	buf := make([]byte, 1+1+len(host)+2)
	buf[0] = AtypDomain
	buf[1] = byte(len(host))
	copy(buf[2:2+len(host)], host)
	copy(buf[2+len(host):], portBuf[:])
	return buf, nil
}

// DecodeTargetBytes decodes a target address ("host:port") from a byte slice or reader.
func DecodeTargetBytes(r io.Reader) (string, error) {
	var atypBuf [1]byte
	if _, err := io.ReadFull(r, atypBuf[:]); err != nil {
		return "", err
	}

	atyp := atypBuf[0]
	var host string

	switch atyp {
	case AtypIPv4:
		var ipBuf [net.IPv4len]byte
		if _, err := io.ReadFull(r, ipBuf[:]); err != nil {
			return "", err
		}
		host = net.IP(ipBuf[:]).String()

	case AtypDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return "", err
		}
		dLen := int(lenBuf[0])
		if dLen == 0 {
			return "", ErrMalformedTarget
		}
		domainBuf := make([]byte, dLen)
		if _, err := io.ReadFull(r, domainBuf); err != nil {
			return "", err
		}
		host = string(domainBuf)

	case AtypIPv6:
		var ipBuf [net.IPv6len]byte
		if _, err := io.ReadFull(r, ipBuf[:]); err != nil {
			return "", err
		}
		host = net.IP(ipBuf[:]).String()

	default:
		return "", fmt.Errorf("%w: 0x%02x", ErrInvalidAddressType, atyp)
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// WriteTarget encodes a destination host:port string onto w.
func WriteTarget(w io.Writer, target string) error {
	buf, err := EncodeTargetBytes(target)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// ReadTarget decodes a destination host:port string from r.
func ReadTarget(r io.Reader) (string, error) {
	return DecodeTargetBytes(r)
}

// WriteUDPPacket encapsulates an individual UDP datagram with its target address and writes it to w.
// Wire layout:
//   [Packet Length: 2 bytes, BigEndian]
//   [AddrType: 1 byte]
//   [AddrLen: 1 byte (for Domain)]
//   [Address: N bytes]
//   [Port: 2 bytes, BigEndian]
//   [Payload: M bytes]
// where Packet Length = len(Address header) + len(Payload).
func WriteUDPPacket(w io.Writer, target string, payload []byte) error {
	addrHeader, err := EncodeTargetBytes(target)
	if err != nil {
		return err
	}

	totalLen := len(addrHeader) + len(payload)
	if totalLen > 65535 {
		return ErrPacketTooLarge
	}

	buf := make([]byte, 2+totalLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(totalLen))
	copy(buf[2:2+len(addrHeader)], addrHeader)
	copy(buf[2+len(addrHeader):], payload)

	_, err = w.Write(buf)
	return err
}

// ReadUDPPacket reads an encapsulated UDP datagram from r.
// It extracts the target address and the payload cleanly.
func ReadUDPPacket(r io.Reader) (string, []byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", nil, err
	}
	packetLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if packetLen < 1+net.IPv4len+2 { // minimum possible size: IPv4 header (7 bytes)
		return "", nil, ErrMalformedTarget
	}

	rawPacket := make([]byte, packetLen)
	if _, err := io.ReadFull(r, rawPacket); err != nil {
		return "", nil, err
	}

	bufReader := bytes.NewReader(rawPacket)
	target, err := DecodeTargetBytes(bufReader)
	if err != nil {
		return "", nil, err
	}

	headerReadLen := packetLen - bufReader.Len()
	payload := make([]byte, len(rawPacket)-headerReadLen)
	copy(payload, rawPacket[headerReadLen:])

	return target, payload, nil
}
