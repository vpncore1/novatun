package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"sync"
	"testing"
)

func TestValidateKey(t *testing.T) {
	// Valid key
	validKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if err := ValidateKey(validKey); err != nil {
		t.Fatalf("ValidateKey rejected valid key: %v", err)
	}

	// Short key
	shortKey := make([]byte, KeySize-1)
	if err := ValidateKey(shortKey); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("expected ErrInvalidKeySize for short key, got %v", err)
	}

	// Long key
	longKey := make([]byte, KeySize+1)
	if err := ValidateKey(longKey); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("expected ErrInvalidKeySize for long key, got %v", err)
	}

	// Weak key (all zeros)
	zeroKey := make([]byte, KeySize)
	if err := ValidateKey(zeroKey); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("expected ErrWeakKey for all-zero key, got %v", err)
	}
}

func TestParsePSK(t *testing.T) {
	rawKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Hex format
	hexStr := hex.EncodeToString(rawKey)
	parsedHex, err := ParsePSK(hexStr)
	if err != nil {
		t.Fatalf("ParsePSK failed for valid hex: %v", err)
	}
	if !bytes.Equal(parsedHex, rawKey) {
		t.Fatalf("parsed hex mismatch: got %x, want %x", parsedHex, rawKey)
	}

	// Std Base64 format
	b64Str := base64.StdEncoding.EncodeToString(rawKey)
	parsedB64, err := ParsePSK(b64Str)
	if err != nil {
		t.Fatalf("ParsePSK failed for valid base64: %v", err)
	}
	if !bytes.Equal(parsedB64, rawKey) {
		t.Fatalf("parsed base64 mismatch: got %x, want %x", parsedB64, rawKey)
	}

	// URL-safe Base64 format
	b64URLStr := base64.URLEncoding.EncodeToString(rawKey)
	parsedB64URL, err := ParsePSK(b64URLStr)
	if err != nil {
		t.Fatalf("ParsePSK failed for valid URL-safe base64: %v", err)
	}
	if !bytes.Equal(parsedB64URL, rawKey) {
		t.Fatalf("parsed URL-safe base64 mismatch")
	}

	// Invalid format
	if _, err := ParsePSK("invalid_string"); !errors.Is(err, ErrInvalidPSKFormat) {
		t.Fatalf("expected ErrInvalidPSKFormat, got %v", err)
	}

	// Empty string
	if _, err := ParsePSK(""); !errors.Is(err, ErrInvalidPSKFormat) {
		t.Fatalf("expected ErrInvalidPSKFormat on empty string, got %v", err)
	}
}

func TestDeriveKey(t *testing.T) {
	secret := []byte("session_master_shared_secret_string")
	salt := []byte("novatun_network_salt_2026")
	info := []byte("novatun_wire_encryption_v1")

	key1, err := DeriveKey(secret, salt, info)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if len(key1) != KeySize {
		t.Fatalf("expected key length %d, got %d", KeySize, len(key1))
	}

	// Ensure deterministic derivation
	key2, err := DeriveKey(secret, salt, info)
	if err != nil {
		t.Fatalf("DeriveKey 2 failed: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatalf("DeriveKey must be deterministic for identical inputs")
	}

	// Different info produces distinct key
	key3, err := DeriveKey(secret, salt, []byte("different_info"))
	if err != nil {
		t.Fatalf("DeriveKey 3 failed: %v", err)
	}
	if bytes.Equal(key1, key3) {
		t.Fatalf("DeriveKey produced identical keys for different info")
	}

	// Empty secret should fail
	if _, err := DeriveKey(nil, salt, info); err == nil {
		t.Fatalf("expected error on nil secret")
	}
}

func TestCipherEncryptDecryptRoundtrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	messages := [][]byte{
		{},
		[]byte("A"),
		[]byte("hello novatun dpi-resistant tunneling"),
		bytes.Repeat([]byte{0x55}, 1400),
		bytes.Repeat([]byte{0xAA}, 60*1024),
	}

	for i, msg := range messages {
		ciphertext, err := cipher.Encrypt(msg)
		if err != nil {
			t.Fatalf("message %d: Encrypt failed: %v", i, err)
		}

		if len(ciphertext) != len(msg)+TagSize {
			t.Fatalf("message %d: ciphertext length %d != expected %d", i, len(ciphertext), len(msg)+TagSize)
		}

		plaintext, err := cipher.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("message %d: Decrypt failed: %v", i, err)
		}

		if !bytes.Equal(plaintext, msg) {
			t.Fatalf("message %d: plaintext mismatch", i)
		}
	}
}

func TestSequentialNonces(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	c1, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher 1 failed: %v", err)
	}
	c2, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher 2 failed: %v", err)
	}

	for i := uint64(0); i < 100; i++ {
		if c1.SendNonce() != i {
			t.Fatalf("iteration %d: expected SendNonce %d, got %d", i, i, c1.SendNonce())
		}
		if c2.RecvNonce() != i {
			t.Fatalf("iteration %d: expected RecvNonce %d, got %d", i, i, c2.RecvNonce())
		}

		msg := []byte("sequential packet payload")
		ciphertext, err := c1.Encrypt(msg)
		if err != nil {
			t.Fatalf("iteration %d: Encrypt failed: %v", i, err)
		}

		plaintext, err := c2.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("iteration %d: Decrypt failed: %v", i, err)
		}

		if !bytes.Equal(plaintext, msg) {
			t.Fatalf("iteration %d: plaintext mismatch", i)
		}
	}
}

func TestNonceExhaustionProtection(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	// Set counter to maximum 64-bit value
	c.SetSendNonce(math.MaxUint64)
	if _, err := c.Encrypt([]byte("test")); !errors.Is(err, ErrNonceExhaustion) {
		t.Fatalf("expected ErrNonceExhaustion on send, got %v", err)
	}
	// Counter must remain at MaxUint64 and never wrap to 0
	if c.SendNonce() != math.MaxUint64 {
		t.Fatalf("counter wrapped around or modified: %d", c.SendNonce())
	}

	c.SetRecvNonce(math.MaxUint64)
	dummyCiphertext := make([]byte, 32)
	if _, err := c.Decrypt(dummyCiphertext); !errors.Is(err, ErrNonceExhaustion) {
		t.Fatalf("expected ErrNonceExhaustion on recv, got %v", err)
	}
	if c.RecvNonce() != math.MaxUint64 {
		t.Fatalf("recv counter wrapped around: %d", c.RecvNonce())
	}
}

func TestCipherTamperingDetection(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	msg := []byte("confidential tunnel data")
	ciphertext, err := c.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 1. Bit flip in ciphertext body
	tamperedBody := append([]byte(nil), ciphertext...)
	tamperedBody[0] ^= 0x01
	c.SetRecvNonce(0) // reset nonce to match encryption
	if _, err := c.Decrypt(tamperedBody); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed on body tampering, got %v", err)
	}

	// 2. Bit flip in AEAD Tag (last 16 bytes)
	tamperedTag := append([]byte(nil), ciphertext...)
	tamperedTag[len(tamperedTag)-1] ^= 0x80
	c.SetRecvNonce(0)
	if _, err := c.Decrypt(tamperedTag); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed on tag tampering, got %v", err)
	}

	// 3. Truncated ciphertext shorter than TagSize
	c.SetRecvNonce(0)
	if _, err := c.Decrypt(ciphertext[:TagSize-1]); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("expected ErrCiphertextTooShort on truncated input, got %v", err)
	}

	// 4. Nonce mismatch (simulate replay or out-of-order)
	c.SetRecvNonce(42) // wrong counter
	if _, err := c.Decrypt(ciphertext); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed on nonce mismatch, got %v", err)
	}
}

func TestConcurrentEncryption(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	const goroutines = 20
	const msgsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			payload := make([]byte, 128)
			for i := 0; i < msgsPerGoroutine; i++ {
				_, _ = rand.Read(payload)
				ct, err := c.Encrypt(payload)
				if err != nil {
					t.Errorf("concurrent Encrypt failed: %v", err)
					return
				}
				if len(ct) != len(payload)+TagSize {
					t.Errorf("invalid ciphertext size: %d", len(ct))
				}
			}
		}()
	}

	wg.Wait()
	expectedTotal := uint64(goroutines * msgsPerGoroutine)
	if c.SendNonce() != expectedTotal {
		t.Fatalf("expected total send nonces %d, got %d", expectedTotal, c.SendNonce())
	}
}

func BenchmarkCipherEncrypt(b *testing.B) {
	key, _ := GenerateKey()
	c, _ := NewCipher(key)
	payload := make([]byte, 1400)
	_, _ = rand.Read(payload)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := c.Encrypt(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCipherDecrypt(b *testing.B) {
	key, _ := GenerateKey()
	c, _ := NewCipher(key)
	payload := make([]byte, 1400)
	_, _ = rand.Read(payload)
	ct, _ := c.Encrypt(payload)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		c.SetRecvNonce(0)
		_, err := c.Decrypt(ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}
