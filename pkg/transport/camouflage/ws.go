package camouflage

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RFC 6455 Constants
const (
	wsOpcodeContinuation = 0x0
	wsOpcodeText         = 0x1
	wsOpcodeBinary       = 0x2
	wsOpcodeClose        = 0x8
	wsOpcodePing         = 0x9
	wsOpcodePong         = 0xA

	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	DefaultWSPath = "/api/v1/stream"
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

var (
	ErrWSClosed             = errors.New("novatun/camouflage: websocket connection closed")
	ErrInvalidWSOpcode      = errors.New("novatun/camouflage: unexpected websocket opcode")
	ErrHandshakeFailed      = errors.New("novatun/camouflage: websocket handshake failed")
	ErrInvalidWSHeader      = errors.New("novatun/camouflage: invalid websocket frame header")
)

// ComputeSecWebSocketAccept calculates the RFC 6455 response key for a given Sec-WebSocket-Key.
func ComputeSecWebSocketAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// WSConn wraps an underlying net.Conn in RFC 6455 WebSocket framing,
// presenting a transparent net.Conn stream abstraction.
type WSConn struct {
	raw      net.Conn
	reader   *bufio.Reader
	isClient bool // client frames MUST be masked; server frames MUST NOT be masked

	readMu  sync.Mutex
	leftover []byte

	writeMu sync.Mutex
}

// NewClientWSConn performs a client-side HTTP/1.1 WebSocket upgrade handshake over rawConn
// and returns an initialized *WSConn implementing net.Conn.
func NewClientWSConn(rawConn net.Conn, host, path string) (*WSConn, error) {
	if path == "" {
		path = DefaultWSPath
	}
	if host == "" {
		host = rawConn.RemoteAddr().String()
	}

	// 1. Generate random 16-byte nonce for Sec-WebSocket-Key
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate ws nonce: %w", err)
	}
	wsKey := base64.StdEncoding.EncodeToString(nonce[:])
	expectedAccept := ComputeSecWebSocketAccept(wsKey)

	// 2. Transmit standard HTTP/1.1 Upgrade Request (mimicking modern Google Chrome)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"User-Agent: %s\r\n"+
		"Accept-Encoding: gzip, deflate, br\r\n"+
		"Accept-Language: en-US,en;q=0.9\r\n\r\n",
		path, host, wsKey, DefaultUserAgent)

	if _, err := rawConn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("write upgrade request: %w", err)
	}

	// 3. Read HTTP/1.1 101 Switching Protocols response
	br := bufio.NewReader(rawConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("%w: status %d %s", ErrHandshakeFailed, resp.StatusCode, resp.Status)
	}

	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("%w: missing or invalid Upgrade header", ErrHandshakeFailed)
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		return nil, fmt.Errorf("%w: Sec-WebSocket-Accept mismatch", ErrHandshakeFailed)
	}

	return &WSConn{
		raw:      rawConn,
		reader:   br,
		isClient: true,
	}, nil
}

// NewServerWSConn wraps a connection where the HTTP 101 response has already been completed.
func NewServerWSConn(rawConn net.Conn, br *bufio.Reader) *WSConn {
	if br == nil {
		br = bufio.NewReader(rawConn)
	}
	return &WSConn{
		raw:      rawConn,
		reader:   br,
		isClient: false,
	}
}

// Write transmits p encapsulated in an RFC 6455 Binary frame (0x02).
// If isClient is true, the frame is masked with a random 4-byte XOR key.
func (ws *WSConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()

	payloadLen := len(p)
	// Header size: 2 bytes base + length extension (0, 2, or 8) + mask key (4 if client)
	var headerLen int
	var lenByte byte

	if payloadLen <= 125 {
		headerLen = 2
		lenByte = byte(payloadLen)
	} else if payloadLen <= 65535 {
		headerLen = 4
		lenByte = 126
	} else {
		headerLen = 10
		lenByte = 127
	}

	maskLen := 0
	if ws.isClient {
		maskLen = 4
	}

	frame := make([]byte, headerLen+maskLen+payloadLen)
	// Byte 0: FIN (0x80) | OpcodeBinary (0x02) -> 0x82
	frame[0] = 0x80 | wsOpcodeBinary

	// Byte 1: Mask bit + initial length byte
	if ws.isClient {
		frame[1] = 0x80 | lenByte
	} else {
		frame[1] = lenByte
	}

	offset := 2
	if lenByte == 126 {
		binary.BigEndian.PutUint16(frame[offset:offset+2], uint16(payloadLen))
		offset += 2
	} else if lenByte == 127 {
		binary.BigEndian.PutUint64(frame[offset:offset+8], uint64(payloadLen))
		offset += 8
	}

	if ws.isClient {
		var maskKey [4]byte
		if _, err := rand.Read(maskKey[:]); err != nil {
			return 0, err
		}
		copy(frame[offset:offset+4], maskKey[:])
		offset += 4

		// Apply XOR masking to payload
		payloadDst := frame[offset:]
		for i := 0; i < payloadLen; i++ {
			payloadDst[i] = p[i] ^ maskKey[i%4]
		}
	} else {
		copy(frame[offset:], p)
	}

	if _, err := ws.raw.Write(frame); err != nil {
		return 0, err
	}

	return len(p), nil
}

// Read reads from the incoming stream of WebSocket Binary frames, stripping framing & masks.
func (ws *WSConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	ws.readMu.Lock()
	defer ws.readMu.Unlock()

	// Drain leftover data from previous frame
	if len(ws.leftover) > 0 {
		n := copy(p, ws.leftover)
		ws.leftover = ws.leftover[n:]
		return n, nil
	}

	// Read next WebSocket frame from wire
	for {
		payload, err := ws.readNextFrame()
		if err != nil {
			return 0, err
		}

		if len(payload) == 0 {
			continue // ping/pong handled or empty frame
		}

		n := copy(p, payload)
		if n < len(payload) {
			ws.leftover = make([]byte, len(payload)-n)
			copy(ws.leftover, payload[n:])
		}
		return n, nil
	}
}

func (ws *WSConn) readNextFrame() ([]byte, error) {
	// Read first 2 bytes: [FIN & RSV & Opcode] [Mask & Length]
	var hdr [2]byte
	if _, err := io.ReadFull(ws.reader, hdr[:]); err != nil {
		return nil, err
	}

	opcode := hdr[0] & 0x0F
	masked := (hdr[1] & 0x80) != 0
	initLen := hdr[1] & 0x7F

	var payloadLen uint64
	switch initLen {
	case 126:
		var extLen [2]byte
		if _, err := io.ReadFull(ws.reader, extLen[:]); err != nil {
			return nil, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(extLen[:]))
	case 127:
		var extLen [8]byte
		if _, err := io.ReadFull(ws.reader, extLen[:]); err != nil {
			return nil, err
		}
		payloadLen = binary.BigEndian.Uint64(extLen[:])
	default:
		payloadLen = uint64(initLen)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(ws.reader, maskKey[:]); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(ws.reader, payload); err != nil {
		return nil, err
	}

	if masked {
		for i := 0; i < len(payload); i++ {
			payload[i] ^= maskKey[i%4]
		}
	}

	switch opcode {
	case wsOpcodeBinary, wsOpcodeContinuation, wsOpcodeText:
		return payload, nil
	case wsOpcodeClose:
		return nil, io.EOF
	case wsOpcodePing:
		// Automatically respond with Pong
		_ = ws.writeControl(wsOpcodePong, payload)
		return nil, nil
	case wsOpcodePong:
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: 0x%x", ErrInvalidWSOpcode, opcode)
	}
}

func (ws *WSConn) writeControl(opcode byte, data []byte) error {
	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()

	maskLen := 0
	if ws.isClient {
		maskLen = 4
	}

	frame := make([]byte, 2+maskLen+len(data))
	frame[0] = 0x80 | (opcode & 0x0F)
	if ws.isClient {
		frame[1] = 0x80 | byte(len(data))
		var mask [4]byte
		_, _ = rand.Read(mask[:])
		copy(frame[2:6], mask[:])
		for i := 0; i < len(data); i++ {
			frame[6+i] = data[i] ^ mask[i%4]
		}
	} else {
		frame[1] = byte(len(data))
		copy(frame[2:], data)
	}

	_, err := ws.raw.Write(frame)
	return err
}

func (ws *WSConn) Close() error {
	_ = ws.writeControl(wsOpcodeClose, nil)
	return ws.raw.Close()
}

func (ws *WSConn) LocalAddr() net.Addr                { return ws.raw.LocalAddr() }
func (ws *WSConn) RemoteAddr() net.Addr               { return ws.raw.RemoteAddr() }
func (ws *WSConn) SetDeadline(t time.Time) error      { return ws.raw.SetDeadline(t) }
func (ws *WSConn) SetReadDeadline(t time.Time) error  { return ws.raw.SetReadDeadline(t) }
func (ws *WSConn) SetWriteDeadline(t time.Time) error { return ws.raw.SetWriteDeadline(t) }

// Compile-time check
var _ net.Conn = (*WSConn)(nil)
