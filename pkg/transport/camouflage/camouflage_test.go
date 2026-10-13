package camouflage_test

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"novatun/pkg/crypto"
	"novatun/pkg/handshake"
	"novatun/pkg/transport"
	"novatun/pkg/transport/camouflage"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	var serverConn net.Conn
	var errS error
	done := make(chan struct{})
	go func() {
		defer close(done)
		serverConn, errS = ln.Accept()
	}()

	clientConn, errC := net.Dial("tcp", ln.Addr().String())
	<-done

	if errC != nil {
		t.Fatalf("Dial: %v", errC)
	}
	if errS != nil {
		t.Fatalf("Accept: %v", errS)
	}
	return clientConn, serverConn
}

func TestWebSocketFramingRoundtrip(t *testing.T) {
	clientRaw, serverRaw := tcpPair(t)

	var clientWS, serverWS *camouflage.WSConn
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		var err error
		clientWS, err = camouflage.NewClientWSConn(clientRaw, "example.com", "/api/v1/stream")
		if err != nil {
			t.Errorf("NewClientWSConn failed: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		fb := camouflage.NewFallbackHandler("/api/v1/stream", "")
		var err error
		serverWS, err = fb.AcceptOrFallback(serverRaw)
		if err != nil {
			t.Errorf("AcceptOrFallback failed: %v", err)
		}
	}()

	wg.Wait()
	if clientWS == nil || serverWS == nil {
		t.Fatal("Failed to establish WebSocket camouflage connections")
	}
	defer clientWS.Close()
	defer serverWS.Close()

	// Transmit arbitrary binary payload
	testPayload := []byte("HIGH_THROUGHPUT_ENCRYPTED_TUNNEL_PAYLOAD_ABC_123")

	go func() {
		_, _ = clientWS.Write(testPayload)
	}()

	recvBuf := make([]byte, 1024)
	n, err := serverWS.Read(recvBuf)
	if err != nil {
		t.Fatalf("serverWS Read failed: %v", err)
	}

	if !bytes.Equal(recvBuf[:n], testPayload) {
		t.Fatalf("Payload mismatch: got %q, want %q", recvBuf[:n], testPayload)
	}

	// Echo test from server to client (unmasked server frame)
	go func() {
		_, _ = serverWS.Write(testPayload)
	}()

	n, err = clientWS.Read(recvBuf)
	if err != nil {
		t.Fatalf("clientWS Read failed: %v", err)
	}
	if !bytes.Equal(recvBuf[:n], testPayload) {
		t.Fatalf("Echo payload mismatch: got %q, want %q", recvBuf[:n], testPayload)
	}
}

func TestActiveProbingFallback(t *testing.T) {
	// Start benign HTTP backend server (mimicking legitimate nginx / website)
	expectedWebResponse := "WELCOME TO LEGITIMATE WEB SERVER"
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expectedWebResponse))
	}))
	defer backendServer.Close()

	fb := camouflage.NewFallbackHandler("/api/v1/stream", backendServer.Listener.Addr().String())

	clientRaw, serverRaw := tcpPair(t)

	go func() {
		// Server checks request
		_, _ = fb.AcceptOrFallback(serverRaw)
	}()

	// Simulate an active DPI prober sending standard HTTP GET /
	req := "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88.1\r\n\r\n"
	go func() {
		_, _ = clientRaw.Write([]byte(req))
	}()

	respBytes, err := io.ReadAll(clientRaw)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// Verify that the prober received legitimate web content from the backend server
	if !bytes.Contains(respBytes, []byte("HTTP/1.1 200 OK")) && !bytes.Contains(respBytes, []byte(expectedWebResponse)) {
		t.Fatalf("Expected legitimate HTTP 200 response from fallback, got: %s", string(respBytes))
	}
}

func TestFullStackWebSocketEncryptedTunnel(t *testing.T) {
	// Full Stack integration:
	// Raw TCP -> WebSocket Camouflage -> Handshake (X25519) -> SecureConn (ChaCha20) -> yamux TunnelSession
	psk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	clientPipe, serverPipe := tcpPair(t)

	var clientWS, serverWS *camouflage.WSConn
	var wsWg sync.WaitGroup
	wsWg.Add(2)

	go func() {
		defer wsWg.Done()
		clientWS, _ = camouflage.NewClientWSConn(clientPipe, "cloudflare.com", "/api/v1/stream")
	}()

	go func() {
		defer wsWg.Done()
		fb := camouflage.NewFallbackHandler("/api/v1/stream", "")
		serverWS, _ = fb.AcceptOrFallback(serverPipe)
	}()

	wsWg.Wait()
	if clientWS == nil || serverWS == nil {
		t.Fatal("Failed WebSocket handshake")
	}
	defer clientWS.Close()
	defer serverWS.Close()

	// Now perform novatun handshake on top of WebSocket!
	var clientC2S, clientS2C, serverC2S, serverS2C *crypto.Cipher
	var hsWg sync.WaitGroup
	hsWg.Add(2)

	go func() {
		defer hsWg.Done()
		clientC2S, clientS2C, _ = handshake.ClientHandshake(clientWS, psk)
	}()
	go func() {
		defer hsWg.Done()
		serverC2S, serverS2C, _ = handshake.ServerHandshake(serverWS, psk, handshake.DefaultClockSkew)
	}()
	hsWg.Wait()

	if clientC2S == nil || serverC2S == nil {
		t.Fatal("Handshake over WebSocket failed")
	}

	// Wrap in SecureConn
	clientSC := transport.NewSecureConn(clientWS, clientC2S, clientS2C)
	serverSC := transport.NewSecureConn(serverWS, serverS2C, serverC2S)
	defer clientSC.Close()
	defer serverSC.Close()

	// Start yamux sessions
	clientSess, err := transport.NewClientSession(clientSC, nil)
	if err != nil {
		t.Fatalf("NewClientSession failed: %v", err)
	}
	defer clientSess.Close()

	serverSess, err := transport.NewServerSession(serverSC, nil)
	if err != nil {
		t.Fatalf("NewServerSession failed: %v", err)
	}
	defer serverSess.Close()

	// Open logical stream and verify end-to-end data transfer
	testData := []byte("VERIFIED_END_TO_END_WEBSOCKET_CAMOUFLAGE_DATA")

	go func() {
		stream, err := serverSess.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		buf := make([]byte, len(testData))
		_, _ = io.ReadFull(stream, buf)
		_, _ = stream.Write(buf) // echo
	}()

	stream, err := clientSess.OpenStream(t.Context())
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Write(testData); err != nil {
		t.Fatalf("Stream Write: %v", err)
	}

	resp := make([]byte, len(testData))
	if _, err := io.ReadFull(stream, resp); err != nil {
		t.Fatalf("Stream Read echo: %v", err)
	}

	if !bytes.Equal(resp, testData) {
		t.Fatalf("Full stack echo mismatch: got %q, want %q", resp, testData)
	}
}
