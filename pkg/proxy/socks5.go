package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 protocol constants (RFC 1928)
const (
	Socks5Version = 0x05

	// Authentication methods
	MethodNoAuth       = 0x00
	MethodNoAcceptable = 0xFF

	// Commands
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	// Reply codes
	ReplySuccess              = 0x00
	ReplyGeneralFailure       = 0x01
	ReplyConnectionNotAllowed = 0x02
	ReplyNetworkUnreachable   = 0x03
	ReplyHostUnreachable      = 0x04
	ReplyConnectionRefused    = 0x05
	ReplyCommandNotSupported  = 0x07
	ReplyAddressNotSupported  = 0x08
)

var (
	ErrNotSocks5     = errors.New("novatun/socks5: protocol version mismatch, not SOCKS5")
	ErrUnsupportedCmd = errors.New("novatun/socks5: unsupported command")
)

// Server is an RFC 1928 SOCKS5 inbound proxy server supporting CONNECT and UDP ASSOCIATE.
type Server struct {
	// TCPHandler is invoked when a client sends a CONNECT command.
	// target is in "host:port" format (domain names preserved without client DNS resolution).
	TCPHandler func(ctx context.Context, clientConn net.Conn, target string) error

	// UDPHandler is invoked when a client sends a UDP ASSOCIATE command.
	// clientTCPConn is the controlling TCP connection (lifecycle must match the UDP association).
	// clientAddrHint is the client's source IP/port hint from the request.
	UDPHandler func(ctx context.Context, clientTCPConn net.Conn, clientAddrHint string) error
}

// Serve accepts incoming connections on listener and serves SOCKS5 clients.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.HandleConn(conn)
	}
}

// HandleConn handles the SOCKS5 handshake on an incoming client connection.
func (s *Server) HandleConn(conn net.Conn) {
	ctx := context.Background()
	cmd, target, err := s.handshake(conn)
	if err != nil {
		_ = conn.Close()
		return
	}

	switch cmd {
	case CmdConnect:
		if s.TCPHandler != nil {
			if err := s.TCPHandler(ctx, conn, target); err != nil {
				_ = conn.Close()
			}
		} else {
			_ = SendReply(conn, ReplyCommandNotSupported)
			_ = conn.Close()
		}

	case CmdUDPAssociate:
		if s.UDPHandler != nil {
			if err := s.UDPHandler(ctx, conn, target); err != nil {
				_ = conn.Close()
			}
		} else {
			_ = SendReply(conn, ReplyCommandNotSupported)
			_ = conn.Close()
		}

	default:
		_ = SendReply(conn, ReplyCommandNotSupported)
		_ = conn.Close()
	}
}

// handshake executes the SOCKS5 method negotiation and request parsing.
func (s *Server) handshake(conn net.Conn) (cmd byte, target string, err error) {
	// 1. Method negotiation
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, "", err
	}
	if hdr[0] != Socks5Version {
		return 0, "", ErrNotSocks5
	}

	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, "", err
	}

	hasNoAuth := false
	for _, m := range methods {
		if m == MethodNoAuth {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		_, _ = conn.Write([]byte{Socks5Version, MethodNoAcceptable})
		return 0, "", errors.New("novatun/socks5: no acceptable auth methods")
	}

	// Reply with NO AUTH (0x05, 0x00)
	if _, err := conn.Write([]byte{Socks5Version, MethodNoAuth}); err != nil {
		return 0, "", err
	}

	// 2. Request details
	var reqHdr [3]byte
	if _, err := io.ReadFull(conn, reqHdr[:]); err != nil {
		return 0, "", err
	}
	if reqHdr[0] != Socks5Version {
		return 0, "", ErrNotSocks5
	}
	cmd = reqHdr[1]
	if cmd != CmdConnect && cmd != CmdUDPAssociate {
		_ = SendReply(conn, ReplyCommandNotSupported)
		return 0, "", fmt.Errorf("%w: 0x%02x", ErrUnsupportedCmd, cmd)
	}

	target, err = ReadTarget(conn)
	if err != nil {
		_ = SendReply(conn, ReplyAddressNotSupported)
		return 0, "", err
	}

	return cmd, target, nil
}

// SendReply sends a standard SOCKS5 response back to the client with a 0.0.0.0:0 bind dummy.
func SendReply(conn io.Writer, replyCode byte) error {
	return SendReplyWithAddr(conn, replyCode, "0.0.0.0:0")
}

// SendReplyWithAddr sends a SOCKS5 response specifying the server's bound address and port (used for UDP ASSOCIATE).
func SendReplyWithAddr(conn io.Writer, replyCode byte, boundAddr string) error {
	host, portStr, err := net.SplitHostPort(boundAddr)
	if err != nil {
		host = "0.0.0.0"
		portStr = "0"
	}
	portNum, _ := strconv.Atoi(portStr)
	port := uint16(portNum)

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)

	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4zero
	}

	if ip4 := ip.To4(); ip4 != nil {
		reply := make([]byte, 1+1+1+1+net.IPv4len+2)
		reply[0] = Socks5Version
		reply[1] = replyCode
		reply[2] = 0x00 // RSV
		reply[3] = AtypIPv4
		copy(reply[4:4+net.IPv4len], ip4)
		copy(reply[4+net.IPv4len:], portBuf[:])
		_, err := conn.Write(reply)
		return err
	}

	reply := make([]byte, 1+1+1+1+net.IPv6len+2)
	reply[0] = Socks5Version
	reply[1] = replyCode
	reply[2] = 0x00 // RSV
	reply[3] = AtypIPv6
	copy(reply[4:4+net.IPv6len], ip.To16())
	copy(reply[4+net.IPv6len:], portBuf[:])
	_, err = conn.Write(reply)
	return err
}
