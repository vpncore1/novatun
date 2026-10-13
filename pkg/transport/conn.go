// Package transport provides the encrypted stream abstraction and multiplexed
// session layer for the novatun tunnel protocol.
//
// SecureConn wraps a raw net.Conn with bidirectional ChaCha20-Poly1305 frame
// encryption (via pkg/frame), presenting a standard net.Conn interface to
// upper layers.  It handles:
//
//   - Automatic payload splitting when writes exceed MaxPayloadSize.
//   - Length-prefixed framing on the wire so readers can reassemble frames
//     arriving across multiple TCP segment boundaries.
//   - Internal read buffering so that small Read() calls against a large
//     decrypted payload are serviced without re-decryption.
//   - Thread-safe concurrent Read and Write via separate mutexes.
//   - Clean resource shutdown on Close.
package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"novatun/pkg/crypto"
	"novatun/pkg/frame"
)

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

const (
	// frameLenSize is the 2-byte big-endian length prefix prepended to every
	// AEAD ciphertext frame on the wire.  This allows the reader to know
	// exactly how many bytes to consume before decryption.
	frameLenSize = 2

	// maxWireFrame is the maximum size of a single ciphertext frame on the
	// wire (excluding the 2-byte length prefix).  Equal to frame.MaxFrameSize.
	maxWireFrame = frame.MaxFrameSize
)

// ────────────────────────────────────────────────────────────────────────────
// Errors
// ────────────────────────────────────────────────────────────────────────────

var (
	// ErrConnClosed is returned when an operation is attempted on a closed SecureConn.
	ErrConnClosed = errors.New("novatun/transport: connection is closed")
)

// ────────────────────────────────────────────────────────────────────────────
// SecureConn
// ────────────────────────────────────────────────────────────────────────────

// SecureConn implements net.Conn over an encrypted frame channel.
//
// Every Write is split into one or more frames (each up to MaxPayloadSize),
// encrypted with the write cipher, length-prefixed, and flushed to the
// underlying connection.
//
// Every Read decodes the next frame from the underlying connection, decrypts
// it, and serves as many bytes as the caller asks for; leftover bytes are
// buffered for subsequent Read calls.
type SecureConn struct {
	raw        net.Conn
	writeCipher *crypto.Cipher // encrypts data we send
	readCipher  *crypto.Cipher // decrypts data we receive

	// writeMu serialises concurrent Write calls so frames are not interleaved.
	writeMu sync.Mutex

	// readMu serialises concurrent Read calls and protects readBuf.
	readMu  sync.Mutex
	readBuf []byte // leftover decrypted payload from the previous frame

	closed atomic.Bool
}

// NewSecureConn wraps a raw network connection with bidirectional encryption.
//
//   - writeCipher encrypts outgoing data (caller→remote).
//   - readCipher  decrypts incoming data (remote→caller).
//
// The caller is responsible for ensuring that the cipher pair matches the
// remote end's pair in the opposite direction (i.e. our writeCipher matches
// their readCipher and vice versa).
func NewSecureConn(raw net.Conn, writeCipher, readCipher *crypto.Cipher) *SecureConn {
	return &SecureConn{
		raw:         raw,
		writeCipher: writeCipher,
		readCipher:  readCipher,
	}
}

// ── net.Conn: Write ──────────────────────────────────────────────────────────

// Write encrypts p into one or more frames and writes them to the underlying
// connection.  Buffers larger than frame.MaxPayloadSize are split
// automatically.  The call is thread-safe.
func (sc *SecureConn) Write(p []byte) (int, error) {
	if sc.closed.Load() {
		return 0, ErrConnClosed
	}

	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	totalWritten := 0
	remaining := p

	for len(remaining) > 0 {
		chunk := remaining
		if len(chunk) > frame.MaxPayloadSize {
			chunk = remaining[:frame.MaxPayloadSize]
		}

		if err := sc.writeFrame(chunk); err != nil {
			return totalWritten, err
		}

		totalWritten += len(chunk)
		remaining = remaining[len(chunk):]
	}

	return totalWritten, nil
}

// writeFrame encrypts a single chunk (must be ≤ MaxPayloadSize) and writes
// [2-byte len prefix] + [ciphertext frame] to the underlying connection.
//
// Must be called under writeMu.
func (sc *SecureConn) writeFrame(payload []byte) error {
	// Encode the frame into a temporary buffer.
	ct, err := frame.EncodeFrameToBytes(payload, sc.writeCipher)
	if err != nil {
		return fmt.Errorf("novatun/transport: frame encode: %w", err)
	}

	// Wire format: [2B big-endian length] [ciphertext]
	var lenBuf [frameLenSize]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(ct)))

	// Write length prefix + ciphertext atomically to the raw conn.
	// We combine them into a single Write to reduce syscall overhead and
	// to avoid partial writes in concurrent environments.
	wireBuf := make([]byte, frameLenSize+len(ct))
	copy(wireBuf[:frameLenSize], lenBuf[:])
	copy(wireBuf[frameLenSize:], ct)

	if _, err := sc.raw.Write(wireBuf); err != nil {
		return fmt.Errorf("novatun/transport: raw write: %w", err)
	}

	return nil
}

// ── net.Conn: Read ───────────────────────────────────────────────────────────

// Read returns decrypted payload bytes.  If the internal read buffer has
// leftover bytes from a previous frame, those are served first.  Otherwise a
// new frame is read from the wire, decrypted, and (partially) returned.
func (sc *SecureConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	sc.readMu.Lock()
	defer sc.readMu.Unlock()

	// Serve from read buffer if available.
	if len(sc.readBuf) > 0 {
		n := copy(p, sc.readBuf)
		sc.readBuf = sc.readBuf[n:]
		if len(sc.readBuf) == 0 {
			sc.readBuf = nil // release backing array
		}
		return n, nil
	}

	if sc.closed.Load() {
		return 0, ErrConnClosed
	}

	// Read next frame from the wire.
	payload, err := sc.readFrame()
	if err != nil {
		return 0, err
	}

	n := copy(p, payload)
	if n < len(payload) {
		// Store the remainder for subsequent Read calls.
		sc.readBuf = make([]byte, len(payload)-n)
		copy(sc.readBuf, payload[n:])
	}
	return n, nil
}

// readFrame reads a single length-prefixed frame from the raw connection,
// then decrypts and returns the payload.
//
// Must be called under readMu.
func (sc *SecureConn) readFrame() ([]byte, error) {
	// 1. Read the 2-byte length prefix.
	var lenBuf [frameLenSize]byte
	if _, err := io.ReadFull(sc.raw, lenBuf[:]); err != nil {
		return nil, err
	}
	frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if frameLen < frame.MinFrameSize || frameLen > maxWireFrame {
		return nil, fmt.Errorf("novatun/transport: invalid frame length %d", frameLen)
	}

	// 2. Read exactly frameLen bytes of ciphertext.
	ctBuf := make([]byte, frameLen)
	if _, err := io.ReadFull(sc.raw, ctBuf); err != nil {
		return nil, fmt.Errorf("novatun/transport: frame body read: %w", err)
	}

	// 3. Decrypt the ciphertext using the frame layer.
	//    We cannot use frame.DecodeFrame here because that expects an io.Reader
	//    and does its own single-Read, but we already consumed the bytes.
	//    Instead, decrypt via the cipher directly and parse the plaintext.
	payload, err := sc.decryptFramePayload(ctBuf)
	if err != nil {
		return nil, fmt.Errorf("novatun/transport: decrypt: %w", err)
	}

	return payload, nil
}

// decryptFramePayload decrypts raw ciphertext (which was produced by
// frame.EncodeFrame) and extracts the plaintext payload, stripping the
// frame header and padding.
func (sc *SecureConn) decryptFramePayload(ct []byte) ([]byte, error) {
	plaintext, err := sc.readCipher.Decrypt(ct)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)

	if len(plaintext) < frame.MinPlaintextSize {
		return nil, errors.New("novatun/transport: malformed decrypted frame")
	}

	payloadLen := int(binary.BigEndian.Uint16(plaintext[0:2]))
	padLen := int(plaintext[2])

	// Structural integrity: header(3) + payloadLen + padLen == len(plaintext)
	if frame.HeaderSize+payloadLen+padLen != len(plaintext) {
		return nil, errors.New("novatun/transport: frame structure mismatch")
	}
	if padLen < frame.MinPadding || padLen > frame.MaxPadding {
		return nil, errors.New("novatun/transport: invalid padding length")
	}
	if payloadLen > frame.MaxPayloadSize {
		return nil, errors.New("novatun/transport: payload length exceeds max")
	}

	out := make([]byte, payloadLen)
	copy(out, plaintext[frame.HeaderSize:frame.HeaderSize+payloadLen])
	return out, nil
}

// ── net.Conn: Close ──────────────────────────────────────────────────────────

// Close closes the secure connection and releases resources.
func (sc *SecureConn) Close() error {
	if sc.closed.Swap(true) {
		return nil // already closed
	}

	err := sc.raw.Close()

	sc.readMu.Lock()
	sc.readBuf = nil
	sc.readMu.Unlock()

	return err
}

// ── net.Conn: Addr & Deadline pass-through ───────────────────────────────────

func (sc *SecureConn) LocalAddr() net.Addr                { return sc.raw.LocalAddr() }
func (sc *SecureConn) RemoteAddr() net.Addr               { return sc.raw.RemoteAddr() }
func (sc *SecureConn) SetDeadline(t time.Time) error      { return sc.raw.SetDeadline(t) }
func (sc *SecureConn) SetReadDeadline(t time.Time) error  { return sc.raw.SetReadDeadline(t) }
func (sc *SecureConn) SetWriteDeadline(t time.Time) error { return sc.raw.SetWriteDeadline(t) }

// ── Accessors ────────────────────────────────────────────────────────────────

// Underlying returns the raw net.Conn beneath the encryption layer.
func (sc *SecureConn) Underlying() net.Conn { return sc.raw }

// IsClosed returns true if the connection has been closed.
func (sc *SecureConn) IsClosed() bool { return sc.closed.Load() }

// Compile-time assertion that *SecureConn implements net.Conn.
var _ net.Conn = (*SecureConn)(nil)
