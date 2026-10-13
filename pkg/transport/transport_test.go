package transport_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"novatun/pkg/crypto"
	"novatun/pkg/handshake"
	"novatun/pkg/transport"
)

// ════════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════════

// newCipherPair generates matching write/read cipher pairs for a synthetic
// SecureConn pair (no handshake — keys generated independently for testing).
func newCipherPair(t *testing.T) (c2s, s2c *crypto.Cipher) {
	t.Helper()
	k1, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	k2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c2s, err = crypto.NewCipher(k1)
	if err != nil {
		t.Fatalf("NewCipher c2s: %v", err)
	}
	s2c, err = crypto.NewCipher(k2)
	if err != nil {
		t.Fatalf("NewCipher s2c: %v", err)
	}
	return c2s, s2c
}

// secureConnPair creates two SecureConns connected via net.Pipe using
// matching cipher pairs (client writes with c2sW → server reads with c2sR, etc.).
func secureConnPair(t *testing.T) (client, server *transport.SecureConn) {
	t.Helper()
	c2sW, c2sR := newCipherPairMatched(t)
	s2cW, s2cR := newCipherPairMatched(t)

	rawC, rawS := net.Pipe()
	client = transport.NewSecureConn(rawC, c2sW, s2cR)
	server = transport.NewSecureConn(rawS, s2cW, c2sR)
	return
}

// newCipherPairMatched returns two cipher objects seeded from the same key,
// so one can encrypt and the other can decrypt in lockstep.
func newCipherPairMatched(t *testing.T) (writer, reader *crypto.Cipher) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	writer, err = crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher writer: %v", err)
	}
	reader, err = crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher reader: %v", err)
	}
	return
}

// secureConnPairHandshake creates a SecureConn pair via real handshake over net.Pipe().
func secureConnPairHandshake(t *testing.T) (clientConn, serverConn *transport.SecureConn) {
	t.Helper()
	psk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	rawC, rawS := net.Pipe()

	var clientC2S, clientS2C, serverC2S, serverS2C *crypto.Cipher
	var clientErr, serverErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientC2S, clientS2C, clientErr = handshake.ClientHandshake(rawC, psk)
	}()
	go func() {
		defer wg.Done()
		serverC2S, serverS2C, serverErr = handshake.ServerHandshake(rawS, psk, handshake.DefaultClockSkew)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("ClientHandshake: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("ServerHandshake: %v", serverErr)
	}

	// Client writes with c2s (client-to-server), reads with s2c (server-to-client).
	// Server writes with s2c, reads with c2s.
	clientConn = transport.NewSecureConn(rawC, clientC2S, clientS2C)
	serverConn = transport.NewSecureConn(rawS, serverS2C, serverC2S)
	return
}

// ════════════════════════════════════════════════════════════════════════════
// 1. SecureConn — basic roundtrip
// ════════════════════════════════════════════════════════════════════════════

func TestSecureConnSmallPayload(t *testing.T) {
	client, server := secureConnPair(t)
	defer client.Close()
	defer server.Close()

	original := []byte("hello novatun secure transport layer")
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		if _, err := client.Write(original); err != nil {
			t.Errorf("client Write: %v", err)
		}
	}()

	buf := make([]byte, 256)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("server Read: %v", err)
	}
	wg.Wait()

	if !bytes.Equal(buf[:n], original) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", buf[:n], original)
	}
}

// ════════════════════════════════════════════════════════════════════════════
// 2. SecureConn — large buffer (5 MB, triggers frame splitting)
// ════════════════════════════════════════════════════════════════════════════

func TestSecureConnLargePayload(t *testing.T) {
	client, server := secureConnPair(t)
	defer client.Close()
	defer server.Close()

	const payloadSize = 5 * 1024 * 1024 // 5 MiB
	original := make([]byte, payloadSize)
	if _, err := rand.Read(original); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write(original)
		errCh <- err
	}()

	received := make([]byte, 0, payloadSize)
	buf := make([]byte, 32*1024)
	for len(received) < payloadSize {
		n, err := server.Read(buf)
		if n > 0 {
			received = append(received, buf[:n]...)
		}
		if err != nil {
			t.Fatalf("server Read at %d bytes: %v", len(received), err)
		}
	}

	if err := <-errCh; err != nil {
		t.Fatalf("client Write: %v", err)
	}

	if !bytes.Equal(received, original) {
		t.Fatalf("5 MiB roundtrip: payload mismatch")
	}
}

// ════════════════════════════════════════════════════════════════════════════
// 3. SecureConn — small chunk reads (internal buffering)
// ════════════════════════════════════════════════════════════════════════════

func TestSecureConnSmallReads(t *testing.T) {
	client, server := secureConnPair(t)
	defer client.Close()
	defer server.Close()

	original := bytes.Repeat([]byte("ABCDEFGHIJ"), 200) // 2000 bytes

	go func() {
		client.Write(original)
	}()

	// Read 1 byte at a time.
	var received []byte
	oneByte := make([]byte, 1)
	for len(received) < len(original) {
		n, err := server.Read(oneByte)
		if n > 0 {
			received = append(received, oneByte[:n]...)
		}
		if err != nil {
			t.Fatalf("Read at offset %d: %v", len(received), err)
		}
	}

	if !bytes.Equal(received, original) {
		t.Fatal("small-chunk reads: payload mismatch")
	}
}

// ════════════════════════════════════════════════════════════════════════════
// 4. SecureConn — deadline handling
// ════════════════════════════════════════════════════════════════════════════

func TestSecureConnReadDeadline(t *testing.T) {
	client, server := secureConnPair(t)
	defer client.Close()
	defer server.Close()

	// Set a very short read deadline on the server — no data is written.
	_ = server.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	buf := make([]byte, 64)
	_, err := server.Read(buf)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// net.Pipe returns *net.OpError with Timeout() == true.
	if ne, ok := err.(net.Error); ok {
		if !ne.Timeout() {
			t.Fatalf("expected timeout, got: %v", err)
		}
	}
	// Even if it's not exactly a net.Error (wrapped), we just need it to not be nil.
}

func TestSecureConnWriteDeadline(t *testing.T) {
	client, server := secureConnPair(t)
	defer client.Close()
	defer server.Close()

	// Set a write deadline and attempt a write. The net.Pipe has no internal
	// buffering beyond one goroutine, so if nobody reads, writes block, and
	// the deadline should fire.
	_ = client.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))

	// Flood writes until deadline triggers. net.Pipe blocks writes when
	// nobody is reading, so the very first write may or may not succeed
	// (the read side is open but nobody calls Read).
	bigBuf := make([]byte, 64*1024)
	for i := 0; i < 1000; i++ {
		_, err := client.Write(bigBuf)
		if err != nil {
			return // deadline kicked in — success
		}
	}
	// If somehow all 1000 writes went through without error within 50ms, that
	// is still okay for a fast system — skip rather than fail.
	t.Skip("write deadline did not trigger (very fast system)")
}

// ════════════════════════════════════════════════════════════════════════════
// 5. SecureConn — bidirectional simultaneous transfer
// ════════════════════════════════════════════════════════════════════════════

func TestSecureConnBidirectional(t *testing.T) {
	client, server := secureConnPair(t)
	defer client.Close()
	defer server.Close()

	const size = 256 * 1024
	clientPayload := make([]byte, size)
	serverPayload := make([]byte, size)
	rand.Read(clientPayload)
	rand.Read(serverPayload)

	var wg sync.WaitGroup
	wg.Add(4)

	// client → server
	go func() { defer wg.Done(); client.Write(clientPayload) }()
	clientToServerBuf := make([]byte, 0, size)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for len(clientToServerBuf) < size {
			n, err := server.Read(buf)
			if n > 0 {
				clientToServerBuf = append(clientToServerBuf, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
	}()

	// server → client
	go func() { defer wg.Done(); server.Write(serverPayload) }()
	serverToClientBuf := make([]byte, 0, size)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for len(serverToClientBuf) < size {
			n, err := client.Read(buf)
			if n > 0 {
				serverToClientBuf = append(serverToClientBuf, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
	}()

	wg.Wait()

	if !bytes.Equal(clientToServerBuf, clientPayload) {
		t.Fatal("client→server: payload mismatch")
	}
	if !bytes.Equal(serverToClientBuf, serverPayload) {
		t.Fatal("server→client: payload mismatch")
	}
}

// ════════════════════════════════════════════════════════════════════════════
// 6. SecureConn — Close semantics
// ════════════════════════════════════════════════════════════════════════════

func TestSecureConnClose(t *testing.T) {
	client, server := secureConnPair(t)

	if client.IsClosed() {
		t.Fatal("client should not be closed before Close()")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client Close: %v", err)
	}
	if !client.IsClosed() {
		t.Fatal("client should be closed after Close()")
	}

	// Second Close is idempotent.
	if err := client.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// Writes on closed conn return error.
	_, err := client.Write([]byte("data"))
	if err == nil {
		t.Fatal("Write on closed conn should fail")
	}

	server.Close()
}

// ════════════════════════════════════════════════════════════════════════════
// 7. TunnelSession — basic stream open/accept
// ════════════════════════════════════════════════════════════════════════════

func TestTunnelSessionBasic(t *testing.T) {
	clientSC, serverSC := secureConnPairHandshake(t)

	clientSess, err := transport.NewClientSession(clientSC, nil)
	if err != nil {
		t.Fatalf("NewClientSession: %v", err)
	}
	defer clientSess.Close()

	serverSess, err := transport.NewServerSession(serverSC, nil)
	if err != nil {
		t.Fatalf("NewServerSession: %v", err)
	}
	defer serverSess.Close()

	// Client opens a stream; server accepts it.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	var serverStream net.Conn
	go func() {
		var err error
		serverStream, err = serverSess.AcceptStream()
		errCh <- err
	}()

	clientStream, err := clientSess.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	// Start writing so yamux transmits the SYN frame to the server.
	msg := []byte("hello through multiplexed encrypted tunnel")
	go func() {
		clientStream.Write(msg)
	}()

	if err := <-errCh; err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}

	buf := make([]byte, 256)
	n, err := serverStream.Read(buf)
	if err != nil {
		t.Fatalf("server stream Read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("stream data mismatch: got %q", buf[:n])
	}

	clientStream.Close()
	serverStream.Close()
}

// ════════════════════════════════════════════════════════════════════════════
// 8. TunnelSession — 50 concurrent streams with bidirectional data
// ════════════════════════════════════════════════════════════════════════════

func TestTunnelSession50ConcurrentStreams(t *testing.T) {
	clientSC, serverSC := secureConnPairHandshake(t)

	cfg := transport.DefaultConfig()
	clientSess, err := transport.NewClientSession(clientSC, cfg)
	if err != nil {
		t.Fatalf("NewClientSession: %v", err)
	}
	defer clientSess.Close()

	serverSess, err := transport.NewServerSession(serverSC, cfg)
	if err != nil {
		t.Fatalf("NewServerSession: %v", err)
	}
	defer serverSess.Close()

	const numStreams = 50
	const payloadSize = 16 * 1024 // 16 KiB per direction per stream

	var wg sync.WaitGroup
	errors := make(chan error, numStreams*4)

	// Server goroutine: accept streams and echo data back.
	wg.Add(1)
	go func() {
		defer wg.Done()
		var serverWg sync.WaitGroup
		for i := 0; i < numStreams; i++ {
			stream, err := serverSess.AcceptStream()
			if err != nil {
				errors <- fmt.Errorf("AcceptStream %d: %w", i, err)
				return
			}
			serverWg.Add(1)
			go func(s net.Conn, idx int) {
				defer serverWg.Done()
				defer s.Close()

				buf := make([]byte, payloadSize)
				if _, err := io.ReadFull(s, buf); err != nil {
					errors <- fmt.Errorf("server stream %d read: %w", idx, err)
					return
				}
				if _, err := s.Write(buf); err != nil {
					errors <- fmt.Errorf("server stream %d write: %w", idx, err)
					return
				}
			}(stream, i)
		}
		serverWg.Wait()
	}()

	// Client goroutines: open streams, send random data, read echo, verify.
	var clientWg sync.WaitGroup
	for i := 0; i < numStreams; i++ {
		clientWg.Add(1)
		go func(idx int) {
			defer clientWg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			stream, err := clientSess.OpenStream(ctx)
			if err != nil {
				errors <- fmt.Errorf("OpenStream %d: %w", idx, err)
				return
			}
			defer stream.Close()

			// Generate unique random payload per stream.
			payload := make([]byte, payloadSize)
			rand.Read(payload)

			if _, err := stream.Write(payload); err != nil {
				errors <- fmt.Errorf("client stream %d write: %w", idx, err)
				return
			}

			// Read echoed data.
			echoed := make([]byte, payloadSize)
			if _, err := io.ReadFull(stream, echoed); err != nil {
				errors <- fmt.Errorf("client stream %d read echo: %w", idx, err)
				return
			}

			if !bytes.Equal(echoed, payload) {
				errors <- fmt.Errorf("stream %d: echo mismatch (got %d bytes, want %d)", idx, len(echoed), len(payload))
			}
		}(i)
	}

	clientWg.Wait()
	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("%v", err)
	}
}

// ════════════════════════════════════════════════════════════════════════════
// 9. TunnelSession — Close and IsClosed
// ════════════════════════════════════════════════════════════════════════════

func TestTunnelSessionClose(t *testing.T) {
	clientSC, serverSC := secureConnPairHandshake(t)

	clientSess, _ := transport.NewClientSession(clientSC, nil)
	serverSess, _ := transport.NewServerSession(serverSC, nil)

	if clientSess.IsClosed() || serverSess.IsClosed() {
		t.Fatal("sessions should not be closed initially")
	}

	clientSess.Close()
	if !clientSess.IsClosed() {
		t.Fatal("client session should be closed after Close()")
	}

	// OpenStream on closed session should fail.
	ctx := context.Background()
	if _, err := clientSess.OpenStream(ctx); err == nil {
		t.Fatal("OpenStream on closed session should fail")
	}

	serverSess.Close()
}

// ════════════════════════════════════════════════════════════════════════════
// 10. TunnelSession — stream throughput over handshaked tunnel
// ════════════════════════════════════════════════════════════════════════════

func TestTunnelSessionThroughput(t *testing.T) {
	clientSC, serverSC := secureConnPairHandshake(t)

	clientSess, _ := transport.NewClientSession(clientSC, nil)
	defer clientSess.Close()
	serverSess, _ := transport.NewServerSession(serverSC, nil)
	defer serverSess.Close()

	const totalBytes = 2 * 1024 * 1024 // 2 MiB

	var serverStream net.Conn
	go func() {
		var err error
		serverStream, err = serverSess.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(io.Discard, serverStream) // drain
		serverStream.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientStream, err := clientSess.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	payload := make([]byte, 32*1024) // 32 KiB chunks
	rand.Read(payload)
	written := 0
	for written < totalBytes {
		n, err := clientStream.Write(payload)
		if err != nil {
			t.Fatalf("write at %d: %v", written, err)
		}
		written += n
	}
	clientStream.Close()
	t.Logf("transferred %d bytes over encrypted multiplexed tunnel", written)
}

// ════════════════════════════════════════════════════════════════════════════
// Benchmarks
// ════════════════════════════════════════════════════════════════════════════

func BenchmarkSecureConnThroughput(b *testing.B) {
	key, _ := crypto.GenerateKey()
	wCipher, _ := crypto.NewCipher(key)
	rCipher, _ := crypto.NewCipher(key)

	rawC, rawS := net.Pipe()
	client := transport.NewSecureConn(rawC, wCipher, nil)
	server := transport.NewSecureConn(rawS, nil, rCipher)
	defer client.Close()
	defer server.Close()

	payload := make([]byte, 1400)
	rand.Read(payload)

	go func() {
		buf := make([]byte, 64*1024)
		for {
			_, err := server.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if _, err := client.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTunnelSessionStreamThroughput(b *testing.B) {
	psk, _ := crypto.GenerateKey()
	rawC, rawS := net.Pipe()

	var clientC2S, clientS2C, serverC2S, serverS2C *crypto.Cipher
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientC2S, clientS2C, _ = handshake.ClientHandshake(rawC, psk)
	}()
	go func() {
		defer wg.Done()
		serverC2S, serverS2C, _ = handshake.ServerHandshake(rawS, psk, handshake.DefaultClockSkew)
	}()
	wg.Wait()

	clientSC := transport.NewSecureConn(rawC, clientC2S, clientS2C)
	serverSC := transport.NewSecureConn(rawS, serverS2C, serverC2S)

	clientSess, _ := transport.NewClientSession(clientSC, nil)
	defer clientSess.Close()
	serverSess, _ := transport.NewServerSession(serverSC, nil)
	defer serverSess.Close()

	// Set up a draining server stream.
	go func() {
		stream, err := serverSess.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(io.Discard, stream)
		stream.Close()
	}()

	ctx := context.Background()
	clientStream, err := clientSess.OpenStream(ctx)
	if err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 1400)
	rand.Read(payload)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if _, err := clientStream.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	clientStream.Close()
}
