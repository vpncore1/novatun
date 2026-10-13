package frame

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"novatun/pkg/crypto"
)

// TestEncodeDecodeRoundtrip tests roundtrip encoding and decoding across various payload sizes:
// empty, 1 byte, 1400 bytes (standard MTU), and 60 KB.
func TestEncodeDecodeRoundtrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	testSizes := []struct {
		name string
		size int
	}{
		{"Empty", 0},
		{"1Byte", 1},
		{"64Bytes", 64},
		{"512Bytes", 512},
		{"1400Bytes_MTU", 1400},
		{"8KB", 8192},
		{"60KB", 60 * 1024},
	}

	for _, tc := range testSizes {
		t.Run(tc.name, func(t *testing.T) {
			encCipher, err := crypto.NewCipher(key)
			if err != nil {
				t.Fatalf("NewCipher failed: %v", err)
			}
			decCipher, err := crypto.NewCipher(key)
			if err != nil {
				t.Fatalf("NewCipher failed: %v", err)
			}

			payload := make([]byte, tc.size)
			if tc.size > 0 {
				if _, err := rand.Read(payload); err != nil {
					t.Fatalf("rand.Read failed: %v", err)
				}
			}

			// Encode
			var buf bytes.Buffer
			if err := EncodeFrame(&buf, payload, encCipher); err != nil {
				t.Fatalf("EncodeFrame failed for size %d: %v", tc.size, err)
			}

			wireLen := buf.Len()
			if wireLen < MinFrameSize || wireLen > MaxFrameSize {
				t.Fatalf("wire length %d out of bounds [%d, %d]", wireLen, MinFrameSize, MaxFrameSize)
			}

			// Decode
			decoded, err := DecodeFrame(&buf, decCipher)
			if err != nil {
				t.Fatalf("DecodeFrame failed for size %d: %v", tc.size, err)
			}

			// Verify byte-for-byte integrity
			if !bytes.Equal(decoded, payload) {
				t.Fatalf("decoded payload does not match original for size %d", tc.size)
			}
		})
	}
}

// TestMultiFrameSession verifies that sequential nonces increment properly across multiple packets.
func TestMultiFrameSession(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	encCipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher enc failed: %v", err)
	}
	decCipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher dec failed: %v", err)
	}

	const numFrames = 50
	for i := 0; i < numFrames; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 100+i*10)

		var buf bytes.Buffer
		if err := EncodeFrame(&buf, payload, encCipher); err != nil {
			t.Fatalf("frame %d: EncodeFrame failed: %v", i, err)
		}

		decoded, err := DecodeFrame(&buf, decCipher)
		if err != nil {
			t.Fatalf("frame %d: DecodeFrame failed: %v", i, err)
		}

		if !bytes.Equal(decoded, payload) {
			t.Fatalf("frame %d: payload mismatch", i)
		}
	}

	if encCipher.SendNonce() != uint64(numFrames) {
		t.Fatalf("expected send nonce %d, got %d", numFrames, encCipher.SendNonce())
	}
	if decCipher.RecvNonce() != uint64(numFrames) {
		t.Fatalf("expected recv nonce %d, got %d", numFrames, decCipher.RecvNonce())
	}
}

// TestCorruptedAEADTag verifies that tampering with the 16-byte Poly1305 AEAD tag fails authentication.
func TestCorruptedAEADTag(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	encCipher, _ := crypto.NewCipher(key)
	decCipher, _ := crypto.NewCipher(key)

	payload := []byte("critical tunnel command payload")
	var buf bytes.Buffer
	if err := EncodeFrame(&buf, payload, encCipher); err != nil {
		t.Fatalf("EncodeFrame failed: %v", err)
	}

	wireBytes := buf.Bytes()
	// Corrupt the last byte of the AEAD Tag
	wireBytes[len(wireBytes)-1] ^= 0x55

	r := bytes.NewReader(wireBytes)
	_, err = DecodeFrame(r, decCipher)
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed on tag corruption, got %v", err)
	}
}

// TestCorruptedCiphertext verifies that tampering with any ciphertext byte fails authentication.
func TestCorruptedCiphertext(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	encCipher, _ := crypto.NewCipher(key)
	decCipher, _ := crypto.NewCipher(key)

	payload := []byte("confidential DPI-resistant payload")
	var buf bytes.Buffer
	if err := EncodeFrame(&buf, payload, encCipher); err != nil {
		t.Fatalf("EncodeFrame failed: %v", err)
	}

	wireBytes := buf.Bytes()
	// Corrupt first byte (which is encrypted Header)
	wireBytes[0] ^= 0xAA

	r := bytes.NewReader(wireBytes)
	_, err = DecodeFrame(r, decCipher)
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed on ciphertext corruption, got %v", err)
	}
}

// TestPaddingRandomness verifies that sequential encodings of the exact same plaintext yield
// different ciphertext lengths and distinct high-entropy ciphertexts (DPI defense).
func TestPaddingRandomness(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	c, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	payload := bytes.Repeat([]byte("static_predictable_plaintext_content_"), 10) // 380 bytes
	const iterations = 60

	lengths := make(map[int]int)
	seenCiphertexts := make(map[string]bool)

	minExpectedLen := HeaderSize + len(payload) + MinPadding + TagSize
	maxExpectedLen := HeaderSize + len(payload) + MaxPadding + TagSize

	for i := 0; i < iterations; i++ {
		var buf bytes.Buffer
		if err := EncodeFrame(&buf, payload, c); err != nil {
			t.Fatalf("iteration %d: EncodeFrame failed: %v", i, err)
		}

		wireBytes := buf.Bytes()
		wireLen := len(wireBytes)

		// Check bounds
		if wireLen < minExpectedLen || wireLen > maxExpectedLen {
			t.Fatalf("iteration %d: wire length %d out of expected range [%d, %d]",
				i, wireLen, minExpectedLen, maxExpectedLen)
		}

		lengths[wireLen]++
		seenCiphertexts[string(wireBytes)] = true
	}

	// Verify that padding variance produces multiple distinct ciphertext lengths
	if len(lengths) < 15 {
		t.Fatalf("insufficient padding randomness: only %d distinct lengths across %d iterations",
			len(lengths), iterations)
	}

	// Verify that sequential encodings never produce identical ciphertext bytes
	if len(seenCiphertexts) != iterations {
		t.Fatalf("expected all %d ciphertexts to be distinct, got %d", iterations, len(seenCiphertexts))
	}
}

// TestPayloadTooLarge verifies that attempting to encode an oversized payload is rejected.
func TestPayloadTooLarge(t *testing.T) {
	key, _ := crypto.GenerateKey()
	c, _ := crypto.NewCipher(key)

	oversized := make([]byte, MaxPayloadSize+1)
	var buf bytes.Buffer
	err := EncodeFrame(&buf, oversized, c)
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}
}

// TestFrameTooShort verifies that frames shorter than MinFrameSize are rejected.
func TestFrameTooShort(t *testing.T) {
	key, _ := crypto.GenerateKey()
	c, _ := crypto.NewCipher(key)

	shortData := make([]byte, MinFrameSize-1)
	r := bytes.NewReader(shortData)
	_, err := DecodeFrame(r, c)
	if !errors.Is(err, ErrFrameTooShort) {
		t.Fatalf("expected ErrFrameTooShort, got %v", err)
	}
}

// TestFrameTooLarge verifies that frames larger than MaxFrameSize are rejected.
func TestFrameTooLarge(t *testing.T) {
	key, _ := crypto.GenerateKey()
	c, _ := crypto.NewCipher(key)

	hugeData := make([]byte, MaxFrameSize+10)
	r := bytes.NewReader(hugeData)
	_, err := DecodeFrame(r, c)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

// TestNilArguments verifies that nil arguments return descriptive errors.
func TestNilArguments(t *testing.T) {
	key, _ := crypto.GenerateKey()
	c, _ := crypto.NewCipher(key)

	var buf bytes.Buffer
	if err := EncodeFrame(nil, []byte("data"), c); !errors.Is(err, ErrNilWriter) {
		t.Fatalf("expected ErrNilWriter, got %v", err)
	}
	if err := EncodeFrame(&buf, []byte("data"), nil); !errors.Is(err, ErrNilCipher) {
		t.Fatalf("expected ErrNilCipher, got %v", err)
	}

	if _, err := DecodeFrame(nil, c); !errors.Is(err, ErrNilReader) {
		t.Fatalf("expected ErrNilReader, got %v", err)
	}
	if _, err := DecodeFrame(&buf, nil); !errors.Is(err, ErrNilCipher) {
		t.Fatalf("expected ErrNilCipher, got %v", err)
	}
}

// TestMemoryLeakCleanPayload verifies that the decoded payload is an independent slice
// not retaining the 65KB frame buffer.
func TestMemoryLeakCleanPayload(t *testing.T) {
	key, _ := crypto.GenerateKey()
	enc, _ := crypto.NewCipher(key)
	dec, _ := crypto.NewCipher(key)

	orig := []byte("short payload")
	var buf bytes.Buffer
	_ = EncodeFrame(&buf, orig, enc)

	decoded, err := DecodeFrame(&buf, dec)
	if err != nil {
		t.Fatalf("DecodeFrame failed: %v", err)
	}

	// Capacity should match payload length closely, ensuring no 65KB buffer retention
	if cap(decoded) > len(decoded)+64 {
		t.Fatalf("potential memory leak: decoded slice cap %d much larger than len %d", cap(decoded), len(decoded))
	}
}

// BenchmarkEncodeFrame measures encoding throughput for MTU (1400B) and 60KB payloads.
func BenchmarkEncodeFrame_1400B(b *testing.B) {
	key, _ := crypto.GenerateKey()
	c, _ := crypto.NewCipher(key)
	payload := make([]byte, 1400)
	_, _ = rand.Read(payload)

	var buf bytes.Buffer
	buf.Grow(MaxFrameSize)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := EncodeFrame(&buf, payload, c); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeFrame_1400B(b *testing.B) {
	key, _ := crypto.GenerateKey()
	enc, _ := crypto.NewCipher(key)
	dec, _ := crypto.NewCipher(key)
	payload := make([]byte, 1400)
	_, _ = rand.Read(payload)

	var buf bytes.Buffer
	_ = EncodeFrame(&buf, payload, enc)
	wireBytes := buf.Bytes()

	reader := bytes.NewReader(wireBytes)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader.Reset(wireBytes)
		dec.SetRecvNonce(0)
		if _, err := DecodeFrame(reader, dec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoundtrip_1400B(b *testing.B) {
	key, _ := crypto.GenerateKey()
	enc, _ := crypto.NewCipher(key)
	dec, _ := crypto.NewCipher(key)
	payload := make([]byte, 1400)
	_, _ = rand.Read(payload)

	var buf bytes.Buffer
	buf.Grow(MaxFrameSize)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := EncodeFrame(&buf, payload, enc); err != nil {
			b.Fatal(err)
		}
		if _, err := DecodeFrame(&buf, dec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoundtrip_60KB(b *testing.B) {
	key, _ := crypto.GenerateKey()
	enc, _ := crypto.NewCipher(key)
	dec, _ := crypto.NewCipher(key)
	payload := make([]byte, 60*1024)
	_, _ = rand.Read(payload)

	var buf bytes.Buffer
	buf.Grow(MaxFrameSize)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := EncodeFrame(&buf, payload, enc); err != nil {
			b.Fatal(err)
		}
		if _, err := DecodeFrame(&buf, dec); err != nil {
			b.Fatal(err)
		}
	}
}
