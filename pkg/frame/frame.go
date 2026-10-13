package frame

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"novatun/pkg/crypto"
)

// Frame constants defining wire layout and bounds.
// The novatun wire layout is completely DPI-resistant:
// It has NO static magic bytes, NO protocol signatures, and NO predictable headers.
//
// Frame Layout (Plaintext before AEAD encryption):
//   [Payload Length: 2 bytes, BigEndian]
//   [Padding Length: 1 byte]
//   [Payload: N bytes]
//   [Padding (Random Bytes): M bytes]
//
// Frame Layout on the Wire (after AEAD encryption):
//   [Encrypted Framed Payload + Padding: (2 + 1 + N + M) bytes]
//   [AEAD Tag: 16 bytes]
const (
	// MaxFrameSize is the maximum allowable wire size for a frame (65535 bytes).
	MaxFrameSize = 65535

	// HeaderSize is the size of the framing header (2 bytes payload length + 1 byte padding length).
	HeaderSize = 3

	// TagSize is the Poly1305 authentication tag size (16 bytes).
	TagSize = crypto.TagSize

	// MinPadding is the minimum dynamic random padding in bytes (traffic analysis / DPI defense).
	MinPadding = 16

	// MaxPadding is the maximum dynamic random padding in bytes.
	MaxPadding = 128

	// MinPlaintextSize is the smallest valid plaintext (HeaderSize + MinPadding + 0 bytes payload).
	MinPlaintextSize = HeaderSize + MinPadding // 19 bytes

	// MinFrameSize is the smallest possible wire frame (MinPlaintextSize + TagSize).
	MinFrameSize = MinPlaintextSize + TagSize // 35 bytes

	// MaxPayloadSize is the maximum payload length that fits inside MaxFrameSize with MinPadding.
	MaxPayloadSize = MaxFrameSize - HeaderSize - MinPadding - TagSize // 65500 bytes
)

// Framing errors.
var (
	ErrNilWriter            = errors.New("novatun/frame: writer cannot be nil")
	ErrNilReader            = errors.New("novatun/frame: reader cannot be nil")
	ErrNilCipher            = errors.New("novatun/frame: cipher cannot be nil")
	ErrPayloadTooLarge      = errors.New("novatun/frame: payload exceeds maximum allowable frame size")
	ErrFrameTooShort        = errors.New("novatun/frame: wire frame smaller than minimum allowable size")
	ErrFrameTooLarge        = errors.New("novatun/frame: wire frame exceeds maximum allowable size")
	ErrMalformedFrame       = errors.New("novatun/frame: malformed frame structure or invalid bounds")
	ErrAuthenticationFailed = errors.New("novatun/frame: frame authentication failed or corrupted ciphertext")
)

// Cipher is an alias to crypto.Cipher for API convenience.
type Cipher = crypto.Cipher

// framePool provides reusable buffers to eliminate allocations during high-throughput packet processing.
var framePool = sync.Pool{
	New: func() any {
		b := make([]byte, MaxFrameSize+1)
		return &b
	},
}

// generatePaddingLength selects a cryptographically secure random padding length in [minLen, maxLen].
func generatePaddingLength(minLen, maxLen int) (int, error) {
	if minLen >= maxLen {
		return minLen, nil
	}
	span := int64(maxLen - minLen + 1)
	nBig, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return 0, fmt.Errorf("novatun/frame: failed to generate random padding length: %w", err)
	}
	return minLen + int(nBig.Int64()), nil
}

// EncodeFrame frames and encrypts a payload, writing the resulting DPI-resistant ciphertext to w.
// It automatically generates dynamic cryptographically secure random padding (16 to 128 bytes)
// to obscure packet sizes and prevent traffic analysis.
func EncodeFrame(w io.Writer, payload []byte, c *Cipher) error {
	if w == nil {
		return ErrNilWriter
	}
	if c == nil {
		return ErrNilCipher
	}
	if len(payload) > MaxPayloadSize {
		return ErrPayloadTooLarge
	}

	// Calculate maximum padding that keeps total frame <= MaxFrameSize
	availablePadding := MaxFrameSize - HeaderSize - TagSize - len(payload)
	if availablePadding < MinPadding {
		return ErrPayloadTooLarge
	}
	maxPad := MaxPadding
	if maxPad > availablePadding {
		maxPad = availablePadding
	}

	padLen, err := generatePaddingLength(MinPadding, maxPad)
	if err != nil {
		return err
	}

	plainLen := HeaderSize + len(payload) + padLen

	// Retrieve scratch buffer from pool
	bufPtr := framePool.Get().(*[]byte)
	defer func() {
		clear((*bufPtr)[:plainLen])
		framePool.Put(bufPtr)
	}()
	plain := (*bufPtr)[:plainLen]

	// 1. [Payload Length: 2 bytes, BigEndian]
	binary.BigEndian.PutUint16(plain[0:2], uint16(len(payload)))

	// 2. [Padding Length: 1 byte]
	plain[2] = byte(padLen)

	// 3. [Payload: N bytes]
	copy(plain[HeaderSize:HeaderSize+len(payload)], payload)

	// 4. [Padding (Random Bytes): M bytes]
	padStart := HeaderSize + len(payload)
	if _, err := rand.Read(plain[padStart:plainLen]); err != nil {
		return fmt.Errorf("novatun/frame: failed to generate random padding bytes: %w", err)
	}

	// 5. Encrypt with ChaCha20-Poly1305 AEAD (appends 16-byte Poly1305 Tag)
	ciphertext, err := c.Encrypt(plain)
	if err != nil {
		return fmt.Errorf("novatun/frame: encryption failed: %w", err)
	}

	// 6. Write final ciphertext frame to writer
	if _, err := w.Write(ciphertext); err != nil {
		return fmt.Errorf("novatun/frame: write failed: %w", err)
	}

	return nil
}

// DecodeFrame reads a ciphertext frame from r, decrypts and authenticates it with AEAD,
// strips the random padding, and extracts the original payload cleanly.
// It enforces strict bounds checks to prevent buffer overflow attacks and memory leaks.
func DecodeFrame(r io.Reader, c *Cipher) ([]byte, error) {
	if r == nil {
		return nil, ErrNilReader
	}
	if c == nil {
		return nil, ErrNilCipher
	}

	bufPtr := framePool.Get().(*[]byte)
	defer func() {
		clear(*bufPtr)
		framePool.Put(bufPtr)
	}()
	buf := *bufPtr

	// Read ciphertext frame from the stream
	n, err := r.Read(buf)
	if n == 0 {
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("novatun/frame: read error: %w", err)
	}

	// Bounds checks on raw frame
	if n > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	if n < MinFrameSize {
		return nil, ErrFrameTooShort
	}

	ciphertext := buf[:n]

	// Decrypt and verify AEAD tag
	plaintext, err := c.Decrypt(ciphertext)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	defer clear(plaintext)

	// Bounds checks on decrypted plaintext
	if len(plaintext) < MinPlaintextSize {
		return nil, ErrMalformedFrame
	}

	payloadLen := int(binary.BigEndian.Uint16(plaintext[0:2]))
	padLen := int(plaintext[2])

	// Strict structural integrity check: HeaderSize + payloadLen + padLen == len(plaintext)
	if HeaderSize+payloadLen+padLen != len(plaintext) {
		return nil, ErrMalformedFrame
	}

	// Validate field constraints
	if payloadLen > MaxPayloadSize {
		return nil, ErrMalformedFrame
	}
	if padLen < MinPadding || padLen > MaxPadding {
		return nil, ErrMalformedFrame
	}
	if HeaderSize+payloadLen > len(plaintext) {
		return nil, ErrMalformedFrame
	}

	// Cleanly extract payload into an exact-sized slice to prevent memory leaks
	// (avoiding retaining references to large frame buffers)
	payload := make([]byte, payloadLen)
	copy(payload, plaintext[HeaderSize:HeaderSize+payloadLen])

	return payload, nil
}

// EncodeFrameToBytes is a convenience helper that encodes payload to a byte slice.
func EncodeFrameToBytes(payload []byte, c *Cipher) ([]byte, error) {
	// Calculate upper bound: HeaderSize + len(payload) + MaxPadding + TagSize
	upperBound := HeaderSize + len(payload) + MaxPadding + TagSize
	if upperBound > MaxFrameSize {
		upperBound = MaxFrameSize
	}
	buf := make([]byte, 0, upperBound)
	w := &sliceWriter{buf: buf}
	if err := EncodeFrame(w, payload, c); err != nil {
		return nil, err
	}
	return w.buf, nil
}

type sliceWriter struct {
	buf []byte
}

func (s *sliceWriter) Write(p []byte) (int, error) {
	s.buf = append(s.buf, p...)
	return len(p), nil
}
