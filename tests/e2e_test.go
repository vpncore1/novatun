package tests

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	novacrypto "novatun/pkg/crypto"
	"novatun/pkg/handshake"
	novaproxy "novatun/pkg/proxy"
	"novatun/pkg/transport"
)

// TestTunnelE2E executes a comprehensive end-to-end integration test:
// 1. HTTP server responding with dynamic content.
// 2. novatun server daemon listening on loopback.
// 3. novatun client with SOCKS5 inbound and auto-reconnecting TunnelManager.
// 4. HTTP client routing through SOCKS5 proxy to origin.
// 5. Test IP and domain-based routing.
// 6. Transparent reconnection test when tunnel physical connection is severed.
func TestTunnelE2E(t *testing.T) {
	// Generate PSK
	psk, err := novacrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// 1. Start backend HTTP test server
	expectedBody := "HELLO FROM NOVATUN TEST SERVER"
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(expectedBody))
	}))
	defer httpServer.Close()

	// 2. Start novatun server listener
	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen novatun server: %v", err)
	}
	defer serverListener.Close()
	serverAddr := serverListener.Addr().String()

	// Track server sessions for testing intentional disconnection
	var serverMu sync.Mutex
	activeServerConns := make([]net.Conn, 0)

	// Server accept loop
	go func() {
		for {
			conn, err := serverListener.Accept()
			if err != nil {
				return
			}
			serverMu.Lock()
			activeServerConns = append(activeServerConns, conn)
			serverMu.Unlock()

			go func(c net.Conn) {
				clientCipher, serverCipher, err := handshake.ServerHandshake(c, psk, handshake.DefaultClockSkew)
				if err != nil {
					_ = c.Close()
					return
				}
				sConn := transport.NewSecureConn(c, serverCipher, clientCipher)
				sess, err := transport.NewServerSession(sConn, nil)
				if err != nil {
					_ = sConn.Close()
					return
				}
				defer sess.Close()

				for {
					stream, err := sess.AcceptStream()
					if err != nil {
						break
					}
					go func(st net.Conn) {
						defer st.Close()
						var typeBuf [1]byte
						if _, err := io.ReadFull(st, typeBuf[:]); err != nil {
							return
						}
						if typeBuf[0] != novaproxy.StreamTypeTCP {
							return
						}
						target, err := novaproxy.ReadTarget(st)
						if err != nil {
							return
						}
						targetConn, err := net.DialTimeout("tcp", target, 5*time.Second)
						if err != nil {
							return
						}
						defer targetConn.Close()
						_ = novaproxy.Relay(st, targetConn)
					}(stream)
				}
			}(conn)
		}
	}()

	// 3. Client TunnelManager and SOCKS5 server setup
	tunnelMgr := newTestTunnelManager(serverAddr, psk)
	defer tunnelMgr.Close()

	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen SOCKS5: %v", err)
	}
	defer socksListener.Close()
	socksAddr := socksListener.Addr().String()

	socksServer := &novaproxy.Server{
		TCPHandler: func(ctx context.Context, clientConn net.Conn, target string) error {
			sess, err := tunnelMgr.GetSession()
			if err != nil {
				_ = novaproxy.SendReply(clientConn, novaproxy.ReplyNetworkUnreachable)
				return err
			}
			streamCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			stream, err := sess.OpenStream(streamCtx)
			if err != nil || sess.IsClosed() {
				_ = sess.Close()
				sess, err = tunnelMgr.GetSession()
				if err != nil {
					_ = novaproxy.SendReply(clientConn, novaproxy.ReplyNetworkUnreachable)
					return err
				}
				stream, err = sess.OpenStream(streamCtx)
				if err != nil {
					_ = novaproxy.SendReply(clientConn, novaproxy.ReplyNetworkUnreachable)
					return err
				}
			}
			defer stream.Close()

			if _, err := stream.Write([]byte{novaproxy.StreamTypeTCP}); err != nil {
				_ = novaproxy.SendReply(clientConn, novaproxy.ReplyGeneralFailure)
				return err
			}

			if err := novaproxy.WriteTarget(stream, target); err != nil {
				_ = sess.Close()
				sess, err = tunnelMgr.GetSession()
				if err != nil {
					_ = novaproxy.SendReply(clientConn, novaproxy.ReplyGeneralFailure)
					return err
				}
				stream, err = sess.OpenStream(streamCtx)
				if err != nil {
					_ = novaproxy.SendReply(clientConn, novaproxy.ReplyGeneralFailure)
					return err
				}
				if _, err := stream.Write([]byte{novaproxy.StreamTypeTCP}); err != nil || novaproxy.WriteTarget(stream, target) != nil {
					_ = novaproxy.SendReply(clientConn, novaproxy.ReplyGeneralFailure)
					return err
				}
			}
			if err := novaproxy.SendReply(clientConn, novaproxy.ReplySuccess); err != nil {
				return err
			}
			return novaproxy.Relay(clientConn, stream)
		},
	}
	go func() {
		_ = socksServer.Serve(socksListener)
	}()

	// 4. Create HTTP Client configured with SOCKS5 Proxy
	socksDialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("SOCKS5 dialer: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return socksDialer.(proxy.ContextDialer).DialContext(ctx, network, addr)
			},
		},
		Timeout: 10 * time.Second,
	}

	// 5. Test 1: Direct IP HTTP request over SOCKS5 tunnel
	t.Run("HTTP_Get_Over_Tunnel", func(t *testing.T) {
		resp, err := httpClient.Get(httpServer.URL)
		if err != nil {
			t.Fatalf("GET over SOCKS5 failed: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll body failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got: %d", resp.StatusCode)
		}
		if string(body) != expectedBody {
			t.Fatalf("Body mismatch: got %q, want %q", string(body), expectedBody)
		}
	})

	// Test 1b: Domain FQDN HTTP request over SOCKS5 tunnel (tests AtypDomain 0x03)
	t.Run("HTTP_Get_Domain_Over_Tunnel", func(t *testing.T) {
		_, port, err := net.SplitHostPort(httpServer.Listener.Addr().String())
		if err != nil {
			t.Fatalf("SplitHostPort: %v", err)
		}
		domainURL := fmt.Sprintf("http://localhost:%s/", port)

		resp, err := httpClient.Get(domainURL)
		if err != nil {
			t.Fatalf("GET over SOCKS5 using domain failed: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll body failed: %v", err)
		}
		if string(body) != expectedBody {
			t.Fatalf("Body mismatch: got %q, want %q", string(body), expectedBody)
		}
	})

	// 6. Test 2: Multiple concurrent requests over multiplexed tunnel
	t.Run("Concurrent_Streams_Throughput", func(t *testing.T) {
		const reqCount = 20
		var wg sync.WaitGroup
		errCh := make(chan error, reqCount)

		for i := 0; i < reqCount; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				resp, err := httpClient.Get(httpServer.URL)
				if err != nil {
					errCh <- fmt.Errorf("req %d failed: %w", idx, err)
					return
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if string(body) != expectedBody {
					errCh <- fmt.Errorf("req %d body mismatch: %s", idx, string(body))
				}
			}(i)
		}

		wg.Wait()
		close(errCh)
		for err := range errCh {
			t.Errorf("Concurrent request error: %v", err)
		}
	})

	// 7. Test 3: Simulated Connection Drop & Transparent Auto-Reconnect
	t.Run("Auto_Reconnect_On_Connection_Drop", func(t *testing.T) {
		// Sever the underlying physical connection
		serverMu.Lock()
		for _, c := range activeServerConns {
			_ = c.Close()
		}
		activeServerConns = nil
		serverMu.Unlock()

		// Allow brief moment for client to detect disconnect
		time.Sleep(100 * time.Millisecond)

		// Subsequent request should automatically trigger reconnection
		resp, err := httpClient.Get(httpServer.URL)
		if err != nil {
			t.Fatalf("GET after reconnect failed: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll body failed: %v", err)
		}
		if string(body) != expectedBody {
			t.Fatalf("Body mismatch after reconnect: got %q, want %q", string(body), expectedBody)
		}
	})
}

// Test helper TunnelManager for E2E
type testTunnelManager struct {
	serverAddr string
	psk        []byte

	mu      sync.RWMutex
	session *transport.TunnelSession
	closed  bool
}

func newTestTunnelManager(serverAddr string, psk []byte) *testTunnelManager {
	return &testTunnelManager{
		serverAddr: serverAddr,
		psk:        psk,
	}
}

func (tm *testTunnelManager) GetSession() (*transport.TunnelSession, error) {
	tm.mu.RLock()
	if tm.closed {
		tm.mu.RUnlock()
		return nil, fmt.Errorf("closed")
	}
	sess := tm.session
	if sess != nil && !sess.IsClosed() {
		tm.mu.RUnlock()
		return sess, nil
	}
	tm.mu.RUnlock()

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.closed {
		return nil, fmt.Errorf("closed")
	}
	if tm.session != nil && !tm.session.IsClosed() {
		return tm.session, nil
	}

	newSess, err := tm.connect()
	if err != nil {
		return nil, err
	}
	tm.session = newSess
	return tm.session, nil
}

func (tm *testTunnelManager) connect() (*transport.TunnelSession, error) {
	rawConn, err := net.DialTimeout("tcp", tm.serverAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	clientCipher, serverCipher, err := handshake.ClientHandshake(rawConn, tm.psk)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	sConn := transport.NewSecureConn(rawConn, clientCipher, serverCipher)
	sess, err := transport.NewClientSession(sConn, nil)
	if err != nil {
		_ = sConn.Close()
		return nil, err
	}
	return sess, nil
}

func (tm *testTunnelManager) Close() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.closed = true
	if tm.session != nil {
		_ = tm.session.Close()
	}
}
