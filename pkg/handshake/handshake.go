// Package handshake implements the novatun session negotiation protocol.
//
// Security model:
//   - X25519 Elliptic-Curve Diffie-Hellman provides Perfect Forward Secrecy (PFS).
//     Ephemeral keypairs are generated per session and discarded immediately after use.
//   - A Pre-Shared Key (PSK) gates the initial client handshake message: the body is
//     encrypted under a PSK-derived key so that any active prober without the PSK sees
//     only 32 bytes of curve point noise followed by indistinguishable AEAD ciphertext.
//   - The server's response body is encrypted under a key derived from the X25519
//     shared secret, so it too is opaque noise to anyone lacking the ephemeral private
//     key (which is never transmitted).
//   - Anti-replay: the client embeds a UTC Unix timestamp; the server rejects anything
//     outside the configured clock-skew window (default ±30 s).  A 16-byte random
//     client salt further defeats offline replay within the window.
//   - Active probing defense (silent-drop): any failure on the server path (short read,
//     bad AEAD, expired timestamp, malformed body) is signalled only via an unexported
//     sentinel error; the caller (or integration code) must close the connection and
//     emit no diagnostic bytes toward the prober.
//   - Session keys: after a successful handshake, HKDF-SHA256 derives two independent
//     32-byte keys (client→server and server→client) from the X25519 shared secret
//     plus both salts, ensuring send and receive ciphers are strictly separate.
//
// Wire layout
//
//	Client message (total: 32 + bodyLen + 16 bytes on wire):
//	  [32 B]  Client Ephemeral Public Key (raw Curve25519 u-coordinate)
//	  [var]   AEAD( PSK-derived key, nonce=0, plaintext=clientBody )
//	          clientBody:
//	            [8 B]  Unix timestamp, big-endian int64
//	            [16 B] Client salt (random)
//	            [M B]  Random padding, M ∈ [minPad, maxPad]
//
//	Server message (total: 32 + bodyLen + 16 bytes on wire):
//	  [32 B]  Server Ephemeral Public Key (raw Curve25519 u-coordinate)
//	  [var]   AEAD( shared-secret-derived key, nonce=0, plaintext=serverBody )
//	          serverBody:
//	            [16 B] Echoed client salt
//	            [16 B] Server salt (random)
//	            [M B]  Random padding, M ∈ [minPad, maxPad]
package handshake

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"novatun/pkg/crypto"
)

// ────────────────────────────────────────────────────────────────────────────
// Protocol constants
// ────────────────────────────────────────────────────────────────────────────

const (
	// x25519PubKeySize is the length of a Curve25519 public key (u-coordinate).
	x25519PubKeySize = 32

	// saltSize is the size of the client and server random salts in bytes.
	saltSize = 16

	// timestampSize is the size of the big-endian int64 Unix timestamp field.
	timestampSize = 8

	// aeadTagSize is the Poly1305 overhead appended by ChaCha20-Poly1305.
	aeadTagSize = 16

	// clientBodyMin is the minimum plaintext size of the client handshake body:
	//   timestamp(8) + clientSalt(16) + minPadding(16) = 40 bytes.
	clientBodyMin = timestampSize + saltSize + minPad

	// serverBodyMin is the minimum plaintext size of the server handshake body:
	//   echoedClientSalt(16) + serverSalt(16) + minPadding(16) = 48 bytes.
	serverBodyMin = saltSize + saltSize + minPad

	// minPad / maxPad — random padding range (same as pkg/frame for consistency).
	minPad = 16
	maxPad = 64

	// DefaultClockSkew is the recommended tolerance for timestamp anti-replay.
	DefaultClockSkew = 30 * time.Second
)

// HKDF info strings — domain-separated so derived keys are context-bound.
const (
	hkdfInfoHandshakeKey = "novatun-handshake-v1-psk-key"
	hkdfInfoC2SKey       = "novatun-session-v1-client-to-server"
	hkdfInfoS2CKey       = "novatun-session-v1-server-to-client"
	hkdfInfoServerHSKey  = "novatun-handshake-v1-server-response-key"
)

// ────────────────────────────────────────────────────────────────────────────
// Sentinel errors
//
// ErrSilentDrop is the only error the server ever returns; the caller MUST
// close the connection and emit zero bytes toward the peer.
// ────────────────────────────────────────────────────────────────────────────

var (
	// ErrSilentDrop is returned by ServerHandshake for ANY validation failure.
	// It encodes no information about the root cause so that the caller can
	// safely close the connection without leaking diagnostic data.
	ErrSilentDrop = errors.New("novatun/handshake: silent drop — connection must be closed immediately")

	// ErrClockSkew is returned by ClientHandshake when the server echoes a
	// client salt that does not match (i.e. the server response failed to
	// authenticate the echoed salt), presented as a generic auth failure to
	// the client caller.
	ErrClientAuthFailed = errors.New("novatun/handshake: server response authentication failed")

	// ErrInvalidPSK is returned when the PSK fails length validation.
	ErrInvalidPSK = errors.New("novatun/handshake: PSK must be exactly 32 bytes and non-zero")
)

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

// ClientHandshake performs the client side of the novatun handshake over conn.
//
// It generates an ephemeral X25519 keypair, sends the client message (public key
// + PSK-encrypted body with timestamp and random salt), reads and verifies the
// server's response, and derives symmetric session ciphers for both directions.
//
// Returns:
//   - clientCipher: used by the client to encrypt data (client → server direction).
//   - serverCipher: used by the client to decrypt data (server → client direction).
func ClientHandshake(conn io.ReadWriter, psk []byte) (clientCipher, serverCipher *crypto.Cipher, err error) {
	if err := validatePSK(psk); err != nil {
		return nil, nil, err
	}

	// ── 1. Generate ephemeral X25519 keypair ─────────────────────────────────
	clientPriv, clientPub, err := generateX25519Keypair()
	if err != nil {
		return nil, nil, fmt.Errorf("novatun/handshake: ephemeral key generation failed: %w", err)
	}

	// ── 2. Build client handshake body (plaintext) ───────────────────────────
	clientSalt, err := randomBytes(saltSize)
	if err != nil {
		return nil, nil, fmt.Errorf("novatun/handshake: client salt generation failed: %w", err)
	}

	padLen, err := randomPaddingLen()
	if err != nil {
		return nil, nil, fmt.Errorf("novatun/handshake: padding length generation failed: %w", err)
	}

	bodyPlain := make([]byte, timestampSize+saltSize+padLen)
	binary.BigEndian.PutUint64(bodyPlain[0:8], uint64(time.Now().UTC().Unix()))
	copy(bodyPlain[8:8+saltSize], clientSalt)
	if _, err := rand.Read(bodyPlain[8+saltSize:]); err != nil {
		return nil, nil, fmt.Errorf("novatun/handshake: padding fill failed: %w", err)
	}

	// ── 3. Encrypt body under PSK-derived key at nonce=0 ─────────────────────
	pskHandshakeKey, err := deriveKeyHKDF(psk, clientPub[:], hkdfInfoHandshakeKey)
	if err != nil {
		return nil, nil, fmt.Errorf("novatun/handshake: PSK key derivation failed: %w", err)
	}
	bodyEnc, err := aeadSeal(pskHandshakeKey, 0, bodyPlain)
	if err != nil {
		return nil, nil, fmt.Errorf("novatun/handshake: body encryption failed: %w", err)
	}
	clear(bodyPlain) // wipe plaintext immediately

	// ── 4. Transmit client message ────────────────────────────────────────────
	msg := make([]byte, x25519PubKeySize+len(bodyEnc))
	copy(msg[0:x25519PubKeySize], clientPub[:])
	copy(msg[x25519PubKeySize:], bodyEnc)
	if _, err := conn.Write(msg); err != nil {
		return nil, nil, fmt.Errorf("novatun/handshake: client message write failed: %w", err)
	}

	// ── 5. Read server response ───────────────────────────────────────────────
	// Server sends: [32 B server pub key] + AEAD ciphertext of serverBody.
	// We must read enough to cover the minimum server response size.
	serverMinMsg := x25519PubKeySize + serverBodyMin + aeadTagSize
	serverMaxMsg := x25519PubKeySize + serverBodyMin + (maxPad - minPad) + aeadTagSize

	serverMsg, err := readBounded(conn, serverMinMsg, serverMaxMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("novatun/handshake: server message read failed: %w", err)
	}

	var serverPub [x25519PubKeySize]byte
	copy(serverPub[:], serverMsg[:x25519PubKeySize])
	serverBodyEnc := serverMsg[x25519PubKeySize:]

	// ── 6. X25519 DH: derive shared secret ───────────────────────────────────
	// Perform exactly one DH operation; keep the result alive for both
	// server-response-key derivation and session-key derivation, then wipe.
	sharedSecret, err := curve25519.X25519(clientPriv[:], serverPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("novatun/handshake: X25519 DH failed: %w", err)
	}
	clear(clientPriv[:]) // ephemeral private key no longer needed
	defer clear(sharedSecret)

	// ── 7. Derive server response encryption key from shared secret ───────────
	// Salt mixes both public keys to bind the key to this specific session
	// and prevent cross-session key confusion.
	sessionSalt := sessionBindingSalt(clientPub[:], serverPub[:])
	serverHSKey, err := deriveKeyHKDF(sharedSecret, sessionSalt, hkdfInfoServerHSKey)
	if err != nil {
		return nil, nil, fmt.Errorf("novatun/handshake: server response key derivation failed: %w", err)
	}

	// ── 8. Decrypt and verify server response body ────────────────────────────
	serverBodyPlain, err := aeadOpen(serverHSKey, 0, serverBodyEnc)
	if err != nil {
		return nil, nil, ErrClientAuthFailed
	}
	defer clear(serverBodyPlain)

	if len(serverBodyPlain) < serverBodyMin {
		return nil, nil, ErrClientAuthFailed
	}

	echoedClientSalt := serverBodyPlain[0:saltSize]
	serverSalt := serverBodyPlain[saltSize : saltSize+saltSize]

	// Verify the server correctly echoed our client salt (constant-time).
	if !constantTimeEqual(echoedClientSalt, clientSalt) {
		return nil, nil, ErrClientAuthFailed
	}

	// ── 9. Derive session ciphers ─────────────────────────────────────────────
	combinedSalt := append(clientSalt, serverSalt...)
	clientCipher, serverCipher, err = deriveSessionCiphers(sharedSecret, combinedSalt)
	if err != nil {
		return nil, nil, fmt.Errorf("novatun/handshake: session cipher derivation failed: %w", err)
	}

	return clientCipher, serverCipher, nil
}

// ServerHandshake performs the server side of the novatun handshake over conn.
//
// On ANY validation failure (short read, bad AEAD, expired timestamp, malformed
// body), it returns ErrSilentDrop.  The caller MUST close conn immediately and
// MUST NOT write any diagnostic bytes.
//
// Returns:
//   - clientCipher: used by the server to decrypt data (client → server direction).
//   - serverCipher: used by the server to encrypt data (server → client direction).
func ServerHandshake(conn io.ReadWriter, psk []byte, allowedClockSkew time.Duration) (clientCipher, serverCipher *crypto.Cipher, err error) {
	if err := validatePSK(psk); err != nil {
		// Bad PSK is a server configuration error, not a probing event.
		return nil, nil, err
	}
	if allowedClockSkew <= 0 {
		allowedClockSkew = DefaultClockSkew
	}

	// ── 1. Read client message ────────────────────────────────────────────────
	// Client sends: [32 B pub key] + AEAD( clientBody ).
	clientMinMsg := x25519PubKeySize + clientBodyMin + aeadTagSize
	clientMaxMsg := x25519PubKeySize + clientBodyMin + (maxPad - minPad) + aeadTagSize

	clientMsg, err := readBounded(conn, clientMinMsg, clientMaxMsg)
	if err != nil {
		return nil, nil, ErrSilentDrop
	}

	var clientPub [x25519PubKeySize]byte
	copy(clientPub[:], clientMsg[:x25519PubKeySize])
	clientBodyEnc := clientMsg[x25519PubKeySize:]

	// ── 2. Derive PSK handshake key and decrypt client body ───────────────────
	pskHandshakeKey, err := deriveKeyHKDF(psk, clientPub[:], hkdfInfoHandshakeKey)
	if err != nil {
		return nil, nil, ErrSilentDrop
	}

	clientBodyPlain, err := aeadOpen(pskHandshakeKey, 0, clientBodyEnc)
	if err != nil {
		// PSK mismatch → silent drop.
		return nil, nil, ErrSilentDrop
	}
	defer clear(clientBodyPlain)

	// ── 3. Parse and validate client body ─────────────────────────────────────
	if len(clientBodyPlain) < clientBodyMin {
		return nil, nil, ErrSilentDrop
	}

	tsUnix := int64(binary.BigEndian.Uint64(clientBodyPlain[0:8]))
	clientSalt := clientBodyPlain[8 : 8+saltSize]

	now := time.Now().UTC().Unix()
	delta := tsUnix - now
	if delta < 0 {
		delta = -delta
	}
	if delta > int64(allowedClockSkew.Seconds()) {
		// Expired or future timestamp → silent drop.
		return nil, nil, ErrSilentDrop
	}

	// ── 4. Generate server ephemeral X25519 keypair ───────────────────────────
	serverPriv, serverPub, err := generateX25519Keypair()
	if err != nil {
		return nil, nil, ErrSilentDrop
	}

	// ── 5. X25519 DH: derive shared secret ───────────────────────────────────
	sharedSecret, err := curve25519.X25519(serverPriv[:], clientPub[:])
	if err != nil {
		return nil, nil, ErrSilentDrop
	}
	clear(serverPriv[:]) // ephemeral private key no longer needed

	// ── 6. Build and encrypt server response body ─────────────────────────────
	serverSalt, err := randomBytes(saltSize)
	if err != nil {
		clear(sharedSecret)
		return nil, nil, ErrSilentDrop
	}

	padLen, err := randomPaddingLen()
	if err != nil {
		clear(sharedSecret)
		return nil, nil, ErrSilentDrop
	}

	serverBodyPlain := make([]byte, saltSize+saltSize+padLen)
	copy(serverBodyPlain[0:saltSize], clientSalt)       // echo client salt
	copy(serverBodyPlain[saltSize:saltSize*2], serverSalt)
	if _, err := rand.Read(serverBodyPlain[saltSize*2:]); err != nil {
		clear(sharedSecret)
		clear(serverBodyPlain)
		return nil, nil, ErrSilentDrop
	}

	sessionSalt := sessionBindingSalt(clientPub[:], serverPub[:])
	serverHSKey, err := deriveKeyHKDF(sharedSecret, sessionSalt, hkdfInfoServerHSKey)
	if err != nil {
		clear(sharedSecret)
		clear(serverBodyPlain)
		return nil, nil, ErrSilentDrop
	}

	serverBodyEnc, err := aeadSeal(serverHSKey, 0, serverBodyPlain)
	clear(serverBodyPlain)
	if err != nil {
		clear(sharedSecret)
		return nil, nil, ErrSilentDrop
	}

	// ── 7. Transmit server message ────────────────────────────────────────────
	serverMsg := make([]byte, x25519PubKeySize+len(serverBodyEnc))
	copy(serverMsg[0:x25519PubKeySize], serverPub[:])
	copy(serverMsg[x25519PubKeySize:], serverBodyEnc)
	if _, err := conn.Write(serverMsg); err != nil {
		clear(sharedSecret)
		return nil, nil, ErrSilentDrop
	}

	// ── 8. Derive session ciphers ─────────────────────────────────────────────
	combinedSalt := append(clientSalt, serverSalt...)
	clientCipher, serverCipher, err = deriveSessionCiphers(sharedSecret, combinedSalt)
	clear(sharedSecret)
	if err != nil {
		return nil, nil, ErrSilentDrop
	}

	return clientCipher, serverCipher, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

// validatePSK checks that the PSK is 32 bytes and non-zero.
func validatePSK(psk []byte) error {
	if len(psk) != crypto.KeySize {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidPSK, len(psk))
	}
	var zero [crypto.KeySize]byte
	if constantTimeEqual(psk, zero[:]) {
		return fmt.Errorf("%w: key is all zeros", ErrInvalidPSK)
	}
	return nil
}

// generateX25519Keypair creates a random X25519 private/public keypair.
// The private key is clamped per RFC 7748.
func generateX25519Keypair() (priv [32]byte, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return priv, pub, fmt.Errorf("rand.Read: %w", err)
	}
	// Apply Curve25519 clamping (RFC 7748 §5).
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pubSlice, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, fmt.Errorf("X25519 basepoint multiply: %w", err)
	}
	copy(pub[:], pubSlice)
	return priv, pub, nil
}

// randomBytes returns n cryptographically secure random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// randomPaddingLen returns a cryptographically secure random integer in [minPad, maxPad].
func randomPaddingLen() (int, error) {
	span := int64(maxPad - minPad + 1)
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return 0, err
	}
	return minPad + int(n.Int64()), nil
}

// deriveKeyHKDF derives a 32-byte key using HKDF-SHA256.
func deriveKeyHKDF(secret, salt []byte, info string) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	key := make([]byte, crypto.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// sessionBindingSalt returns a 64-byte salt that binds the session to both
// ephemeral public keys, preventing cross-session key confusion.
func sessionBindingSalt(clientPub, serverPub []byte) []byte {
	salt := make([]byte, x25519PubKeySize*2)
	copy(salt[:x25519PubKeySize], clientPub)
	copy(salt[x25519PubKeySize:], serverPub)
	return salt
}

// aeadSeal encrypts and authenticates plaintext with a 32-byte key and a given nonce counter.
func aeadSeal(key []byte, nonceCounter uint64, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	var nonce [crypto.NonceSize]byte
	crypto.FormatNonce(nonceCounter, &nonce)
	return aead.Seal(nil, nonce[:], plaintext, nil), nil
}

// aeadOpen decrypts and verifies ciphertext with a 32-byte key and a given nonce counter.
func aeadOpen(key []byte, nonceCounter uint64, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aeadTagSize {
		return nil, errors.New("ciphertext too short")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	var nonce [crypto.NonceSize]byte
	crypto.FormatNonce(nonceCounter, &nonce)
	return aead.Open(nil, nonce[:], ciphertext, nil)
}

// deriveSessionCiphers derives two independent session ciphers from the X25519
// shared secret and the combined (clientSalt || serverSalt) material.
//
// The two HKDF info strings are distinct so the derived keys are guaranteed
// to differ even when the shared secret is identical across invocations
// (which cannot happen with ephemeral keys, but is good practice).
func deriveSessionCiphers(sharedSecret, combinedSalt []byte) (clientToServer, serverToClient *crypto.Cipher, err error) {
	c2sKey, err := deriveKeyHKDF(sharedSecret, combinedSalt, hkdfInfoC2SKey)
	if err != nil {
		return nil, nil, fmt.Errorf("c2s key derivation: %w", err)
	}
	s2cKey, err := deriveKeyHKDF(sharedSecret, combinedSalt, hkdfInfoS2CKey)
	if err != nil {
		clear(c2sKey)
		return nil, nil, fmt.Errorf("s2c key derivation: %w", err)
	}

	c2sCipher, err := crypto.NewCipher(c2sKey)
	clear(c2sKey)
	if err != nil {
		clear(s2cKey)
		return nil, nil, fmt.Errorf("c2s cipher init: %w", err)
	}

	s2cCipher, err := crypto.NewCipher(s2cKey)
	clear(s2cKey)
	if err != nil {
		return nil, nil, fmt.Errorf("s2c cipher init: %w", err)
	}

	return c2sCipher, s2cCipher, nil
}

// readBounded reads exactly between minLen and maxLen bytes from r into a single
// call, returning an error if fewer than minLen bytes arrive or the stream
// returns more than maxLen bytes.
//
// Design note: novatun handshake messages are short and transmitted atomically.
// For a production stream transport (e.g. TCP), a length-prefixed or fixed-size
// framing would replace this helper.  Here we use io.ReadFull on the maximum
// expected size and check the actual byte count.
func readBounded(r io.Reader, minLen, maxLen int) ([]byte, error) {
	buf := make([]byte, maxLen)
	// Read up to maxLen bytes; we expect the peer to send exactly one message.
	n, err := io.ReadAtLeast(r, buf, minLen)
	if err != nil {
		return nil, fmt.Errorf("readBounded: got %d bytes (min %d): %w", n, minLen, err)
	}
	return buf[:n], nil
}

// constantTimeEqual compares two byte slices in constant time.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
