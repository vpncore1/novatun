package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Cryptographic constants for novatun ChaCha20-Poly1305 AEAD.
const (
	// KeySize is the required pre-shared key (PSK) length in bytes (256 bits).
	KeySize = chacha20poly1305.KeySize // 32 bytes

	// NonceSize is the ChaCha20-Poly1305 standard nonce length in bytes (96 bits).
	NonceSize = chacha20poly1305.NonceSize // 12 bytes

	// TagSize is the Poly1305 authentication tag length in bytes (128 bits).
	TagSize = chacha20poly1305.Overhead // 16 bytes
)

// Common cryptographic errors.
var (
	ErrInvalidKeySize       = errors.New("novatun/crypto: key must be exactly 32 bytes")
	ErrWeakKey              = errors.New("novatun/crypto: weak pre-shared key (all zeros)")
	ErrNonceExhaustion      = errors.New("novatun/crypto: 64-bit nonce counter exhausted; rekey required")
	ErrCiphertextTooShort   = errors.New("novatun/crypto: ciphertext shorter than tag size")
	ErrAuthenticationFailed = errors.New("novatun/crypto: message authentication failed")
	ErrInvalidPSKFormat     = errors.New("novatun/crypto: invalid PSK format (must be 32-byte hex or base64)")
)

// Cipher wraps ChaCha20-Poly1305 AEAD with atomic sequential nonces.
// Each direction (send and receive) maintains an independent 64-bit counter
// to guarantee deterministic nonce generation and strictly avoid nonce reuse.
type Cipher struct {
	aead      cipher.AEAD
	sendNonce atomic.Uint64
	recvNonce atomic.Uint64
}

// NewCipher creates a new Cipher initialized with a validated 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("novatun/crypto: failed to initialize chacha20poly1305: %w", err)
	}
	return &Cipher{
		aead: aead,
	}, nil
}

// NewCipherFromPSK parses a hex or base64 encoded 32-byte pre-shared key
// and returns an initialized Cipher.
func NewCipherFromPSK(pskStr string) (*Cipher, error) {
	key, err := ParsePSK(pskStr)
	if err != nil {
		return nil, err
	}
	return NewCipher(key)
}

// FormatNonce encodes a 64-bit counter into a 12-byte ChaCha20-Poly1305 nonce.
// Layout: [Bytes 0..3: 0x00] [Bytes 4..11: BigEndian 64-bit uint counter].
func FormatNonce(counter uint64, out *[NonceSize]byte) {
	out[0] = 0
	out[1] = 0
	out[2] = 0
	out[3] = 0
	binary.BigEndian.PutUint64(out[4:12], counter)
}

// NextSendNonce atomically advances and returns the next sequential send nonce counter.
// Returns ErrNonceExhaustion if the 64-bit counter has reached math.MaxUint64 to
// strictly avoid catastrophic nonce reuse.
func (c *Cipher) NextSendNonce() (uint64, error) {
	for {
		cur := c.sendNonce.Load()
		if cur == math.MaxUint64 {
			return 0, ErrNonceExhaustion
		}
		if c.sendNonce.CompareAndSwap(cur, cur+1) {
			return cur, nil
		}
	}
}

// NextRecvNonce atomically advances and returns the next sequential receive nonce counter.
// Returns ErrNonceExhaustion if the 64-bit counter has reached math.MaxUint64.
func (c *Cipher) NextRecvNonce() (uint64, error) {
	for {
		cur := c.recvNonce.Load()
		if cur == math.MaxUint64 {
			return 0, ErrNonceExhaustion
		}
		if c.recvNonce.CompareAndSwap(cur, cur+1) {
			return cur, nil
		}
	}
}

// Encrypt encrypts and authenticates plaintext using the next sequential send nonce.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonceNum, err := c.NextSendNonce()
	if err != nil {
		return nil, err
	}
	return c.EncryptWithNonce(plaintext, nonceNum)
}

// EncryptWithNonce encrypts and authenticates plaintext using a specific 64-bit nonce counter.
func (c *Cipher) EncryptWithNonce(plaintext []byte, nonceNum uint64) ([]byte, error) {
	var nonce [NonceSize]byte
	FormatNonce(nonceNum, &nonce)
	return c.aead.Seal(nil, nonce[:], plaintext, nil), nil
}

// EncryptTo appends the encrypted and authenticated ciphertext of plaintext to dst
// using the next sequential send nonce.
func (c *Cipher) EncryptTo(dst []byte, plaintext []byte) ([]byte, error) {
	nonceNum, err := c.NextSendNonce()
	if err != nil {
		return nil, err
	}
	var nonce [NonceSize]byte
	FormatNonce(nonceNum, &nonce)
	return c.aead.Seal(dst, nonce[:], plaintext, nil), nil
}

// Decrypt decrypts and authenticates ciphertext using the next sequential receive nonce.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceNum, err := c.NextRecvNonce()
	if err != nil {
		return nil, err
	}
	return c.DecryptWithNonce(ciphertext, nonceNum)
}

// DecryptWithNonce decrypts and authenticates ciphertext using a specific 64-bit nonce counter.
func (c *Cipher) DecryptWithNonce(ciphertext []byte, nonceNum uint64) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, ErrCiphertextTooShort
	}
	var nonce [NonceSize]byte
	FormatNonce(nonceNum, &nonce)
	plaintext, err := c.aead.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	return plaintext, nil
}

// DecryptTo appends the decrypted plaintext of ciphertext to dst
// using the next sequential receive nonce.
func (c *Cipher) DecryptTo(dst []byte, ciphertext []byte) ([]byte, error) {
	nonceNum, err := c.NextRecvNonce()
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < TagSize {
		return nil, ErrCiphertextTooShort
	}
	var nonce [NonceSize]byte
	FormatNonce(nonceNum, &nonce)
	plaintext, err := c.aead.Open(dst, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	return plaintext, nil
}

// SendNonce returns the current sequential send nonce counter.
func (c *Cipher) SendNonce() uint64 {
	return c.sendNonce.Load()
}

// RecvNonce returns the current sequential receive nonce counter.
func (c *Cipher) RecvNonce() uint64 {
	return c.recvNonce.Load()
}

// SetSendNonce manually sets the sequential send nonce counter.
func (c *Cipher) SetSendNonce(v uint64) {
	c.sendNonce.Store(v)
}

// SetRecvNonce manually sets the sequential receive nonce counter.
func (c *Cipher) SetRecvNonce(v uint64) {
	c.recvNonce.Store(v)
}

// ResetNonces resets both send and receive nonce counters to zero.
func (c *Cipher) ResetNonces() {
	c.sendNonce.Store(0)
	c.recvNonce.Store(0)
}

// ValidateKey validates that a pre-shared key is exactly 32 bytes
// and is not all zeros (which signifies a weak or placeholder key).
func ValidateKey(key []byte) error {
	if len(key) != KeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, KeySize, len(key))
	}
	var zeroKey [KeySize]byte
	if subtle.ConstantTimeCompare(key, zeroKey[:]) == 1 {
		return ErrWeakKey
	}
	return nil
}

// DeriveKey derives a cryptographically strong 32-byte key from a secret, salt, and info
// using HKDF-SHA256 (RFC 5869).
func DeriveKey(secret, salt, info []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("novatun/crypto: secret cannot be empty")
	}
	hkdfReader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("novatun/crypto: key derivation failed: %w", err)
	}
	return key, nil
}

// GenerateKey generates a cryptographically secure random 32-byte key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("novatun/crypto: failed to generate secure key: %w", err)
	}
	return key, nil
}

// ParsePSK parses and validates a 32-byte pre-shared key from a hex or base64 encoded string.
func ParsePSK(pskStr string) ([]byte, error) {
	trimmed := strings.TrimSpace(pskStr)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: empty key", ErrInvalidPSKFormat)
	}

	// Try hex decoding (64 hex characters)
	if len(trimmed) == 64 {
		decoded, err := hex.DecodeString(trimmed)
		if err == nil && len(decoded) == KeySize {
			if err := ValidateKey(decoded); err != nil {
				return nil, err
			}
			return decoded, nil
		}
	}

	// Try standard base64 decoding (44 characters)
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil && len(decoded) == KeySize {
		if err := ValidateKey(decoded); err != nil {
			return nil, err
		}
		return decoded, nil
	}

	// Try URL-safe base64 decoding
	decoded, err = base64.URLEncoding.DecodeString(trimmed)
	if err == nil && len(decoded) == KeySize {
		if err := ValidateKey(decoded); err != nil {
			return nil, err
		}
		return decoded, nil
	}

	return nil, ErrInvalidPSKFormat
}
