package tests

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	novacrypto "novatun/pkg/crypto"
	"novatun/pkg/handshake"
	novaproxy "novatun/pkg/proxy"
	"novatun/pkg/transport"
)

// TestTunnelUDPE2E executes end-to-end integration tests for UDP routing over novatun:
// 1. Local UDP echo server.
// 2. novatun server listening on loopback (handling both TCP and UDP streams).
// 3. novatun client with SOCKS5 inbound (supporting CONNECT and UDP ASSOCIATE).
// 4. SOCKS5 client executing UDP ASSOCIATE to send datagrams.
// 5. Verification of uncorrupted echo responses and correct addressing.
// 6. Verification of concurrent UDP packets (simulating DNS/gaming traffic).
func TestTunnelUDPE2E(t *testing.T) {
	// Generate PSK
	psk, err := novacrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// 1. Start backend UDP echo server
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP echo server: %v", err)
	}
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().String()

	// Echo server loop
	echoDone := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-echoDone:
				return
			default:
			}
			_ = echoConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, clientAddr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			// Echo back payload to clientAddr
			_, _ = echoConn.WriteToUDP(buf[:n], clientAddr)
		}
	}()
	defer close(echoDone)

	// 2. Start novatun server listener
	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen novatun server: %v", err)
	}
	defer serverListener.Close()
	serverAddr := serverListener.Addr().String()

	go func() {
		for {
			conn, err := serverListener.Accept()
			if err != nil {
				return
			}
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
					go handleTestServerStream(stream)
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
			// Not used in UDP test
			return nil
		},
		UDPHandler: func(ctx context.Context, clientTCPConn net.Conn, clientAddrHint string) error {
			tcpLocalAddr := clientTCPConn.LocalAddr().(*net.TCPAddr)
			udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: tcpLocalAddr.IP, Port: 0})
			if err != nil {
				_ = novaproxy.SendReply(clientTCPConn, novaproxy.ReplyGeneralFailure)
				return err
			}
			defer udpListener.Close()

			bndAddr := udpListener.LocalAddr().String()

			sess, err := tunnelMgr.GetSession()
			if err != nil {
				_ = novaproxy.SendReply(clientTCPConn, novaproxy.ReplyNetworkUnreachable)
				return err
			}

			streamCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			stream, err := sess.OpenStream(streamCtx)
			if err != nil {
				_ = novaproxy.SendReply(clientTCPConn, novaproxy.ReplyNetworkUnreachable)
				return err
			}
			defer stream.Close()

			// Write StreamTypeUDP (0x02)
			if _, err := stream.Write([]byte{novaproxy.StreamTypeUDP}); err != nil {
				_ = novaproxy.SendReply(clientTCPConn, novaproxy.ReplyGeneralFailure)
				return err
			}

			if err := novaproxy.SendReplyWithAddr(clientTCPConn, novaproxy.ReplySuccess, bndAddr); err != nil {
				return err
			}

			tcpClosed := make(chan struct{})
			go func() {
				buf := make([]byte, 1)
				for {
					_, err := clientTCPConn.Read(buf)
					if err != nil {
						break
					}
				}
				close(tcpClosed)
				_ = udpListener.Close()
				_ = stream.Close()
			}()

			var clientUDPSrc net.Addr
			var clientSrcMu sync.RWMutex

			// Read from local UDP socket -> tunnel stream
			go func() {
				packetBuf := make([]byte, 65535)
				for {
					n, srcAddr, err := udpListener.ReadFrom(packetBuf)
					if err != nil {
						return
					}
					clientSrcMu.Lock()
					clientUDPSrc = srcAddr
					clientSrcMu.Unlock()

					target, payload, err := novaproxy.ParseSocks5UDPPacket(packetBuf[:n])
					if err != nil {
						continue
					}
					if err := novaproxy.WriteUDPPacket(stream, target, payload); err != nil {
						return
					}
				}
			}()

			// Read from tunnel stream -> local UDP socket
			go func() {
				for {
					target, payload, err := novaproxy.ReadUDPPacket(stream)
					if err != nil {
						return
					}
					socks5Packet, err := novaproxy.EncodeSocks5UDPPacket(target, payload)
					if err != nil {
						continue
					}
					clientSrcMu.RLock()
					dst := clientUDPSrc
					clientSrcMu.RUnlock()
					if dst != nil {
						_, _ = udpListener.WriteTo(socks5Packet, dst)
					}
				}
			}()

			<-tcpClosed
			return nil
		},
	}

	go func() {
		_ = socksServer.Serve(socksListener)
	}()

	// 4. Test 1: SOCKS5 UDP ASSOCIATE + Single Datagram Roundtrip
	t.Run("UDP_Single_Packet_Roundtrip", func(t *testing.T) {
		socksTCPConn, udpRelayAddr := performSocks5UDPAssociate(t, socksAddr)
		defer socksTCPConn.Close()

		// Local UDP socket representing client app
		clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("ListenUDP client: %v", err)
		}
		defer clientUDP.Close()

		relayUDPAddr, err := net.ResolveUDPAddr("udp", udpRelayAddr)
		if err != nil {
			t.Fatalf("ResolveUDPAddr: %v", err)
		}

		message := []byte("VOICE_CHAT_FRAME_TEST_PACKET_001")
		reqPacket, err := novaproxy.EncodeSocks5UDPPacket(echoAddr, message)
		if err != nil {
			t.Fatalf("EncodeSocks5UDPPacket: %v", err)
		}

		// Send packet to relayUDPAddr
		if _, err := clientUDP.WriteToUDP(reqPacket, relayUDPAddr); err != nil {
			t.Fatalf("WriteToUDP: %v", err)
		}

		// Read response
		respBuf := make([]byte, 65535)
		_ = clientUDP.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := clientUDP.ReadFromUDP(respBuf)
		if err != nil {
			t.Fatalf("ReadFromUDP echo response: %v", err)
		}

		respTarget, respPayload, err := novaproxy.ParseSocks5UDPPacket(respBuf[:n])
		if err != nil {
			t.Fatalf("ParseSocks5UDPPacket response: %v", err)
		}

		if string(respPayload) != string(message) {
			t.Fatalf("Echo payload mismatch: got %q, want %q", string(respPayload), string(message))
		}

		// Verify target matches echo server
		h1, p1, _ := net.SplitHostPort(respTarget)
		h2, p2, _ := net.SplitHostPort(echoAddr)
		if (!net.ParseIP(h1).Equal(net.ParseIP(h2))) || p1 != p2 {
			t.Fatalf("Source address mismatch: got %s, want %s", respTarget, echoAddr)
		}
	})

	// 5. Test 2: Concurrent UDP Datagrams (simulating gaming/DNS high throughput)
	t.Run("UDP_Concurrent_Packets", func(t *testing.T) {
		socksTCPConn, udpRelayAddr := performSocks5UDPAssociate(t, socksAddr)
		defer socksTCPConn.Close()

		relayUDPAddr, err := net.ResolveUDPAddr("udp", udpRelayAddr)
		if err != nil {
			t.Fatalf("ResolveUDPAddr: %v", err)
		}

		clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("ListenUDP: %v", err)
		}
		defer clientUDP.Close()

		const count = 30
		errCh := make(chan error, count)

		// Goroutine to read echo replies
		var received sync.Map
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			buf := make([]byte, 2048)
			for i := 0; i < count; i++ {
				_ = clientUDP.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, _, err := clientUDP.ReadFromUDP(buf)
				if err != nil {
					errCh <- fmt.Errorf("read error after %d received: %w", i, err)
					return
				}
				_, payload, err := novaproxy.ParseSocks5UDPPacket(buf[:n])
				if err != nil {
					errCh <- fmt.Errorf("parse packet: %w", err)
					return
				}
				received.Store(string(payload), true)
			}
		}()

		// Send packets concurrently
		var sendWg sync.WaitGroup
		for i := 0; i < count; i++ {
			sendWg.Add(1)
			go func(idx int) {
				defer sendWg.Done()
				msg := fmt.Sprintf("GAMING_PACKET_SEQ_%05d", idx)
				packet, err := novaproxy.EncodeSocks5UDPPacket(echoAddr, []byte(msg))
				if err != nil {
					errCh <- fmt.Errorf("client %d encode: %w", idx, err)
					return
				}
				if _, err := clientUDP.WriteToUDP(packet, relayUDPAddr); err != nil {
					errCh <- fmt.Errorf("client %d write: %w", idx, err)
					return
				}
			}(i)
		}
		sendWg.Wait()
		<-readDone
		close(errCh)

		for err := range errCh {
			t.Errorf("Concurrent UDP error: %v", err)
		}

		for i := 0; i < count; i++ {
			msg := fmt.Sprintf("GAMING_PACKET_SEQ_%05d", i)
			if _, ok := received.Load(msg); !ok {
				t.Errorf("Missing echo response for: %s", msg)
			}
		}
	})
}

// performSocks5UDPAssociate performs the SOCKS5 handshake requesting UDP ASSOCIATE (0x03)
// and returns the controlling TCP connection and the allocated UDP relay address ("host:port").
func performSocks5UDPAssociate(t *testing.T, socksAddr string) (net.Conn, string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial SOCKS5 TCP: %v", err)
	}

	// 1. Method negotiation: [VER: 0x05] [NMETHODS: 1] [METHOD: 0x00]
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		t.Fatalf("Write method negotiation: %v", err)
	}

	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		conn.Close()
		t.Fatalf("Read method negotiation response: %v", err)
	}
	if methodResp[0] != 0x05 || methodResp[1] != 0x00 {
		conn.Close()
		t.Fatalf("SOCKS5 auth rejected: %v", methodResp)
	}

	// 2. Request UDP ASSOCIATE:
	// [VER: 0x05] [CMD: 0x03] [RSV: 0x00] [ATYP: 0x01] [4B 0.0.0.0] [2B 0]
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		t.Fatalf("Write UDP ASSOCIATE request: %v", err)
	}

	// 3. Read reply: [VER: 0x05] [REP: 0x00] [RSV: 0x00] [ATYP & ADDR & PORT]
	var repHdr [3]byte
	if _, err := io.ReadFull(conn, repHdr[:]); err != nil {
		conn.Close()
		t.Fatalf("Read reply header: %v", err)
	}
	if repHdr[0] != 0x05 || repHdr[1] != 0x00 {
		conn.Close()
		t.Fatalf("UDP ASSOCIATE failed with rep code: 0x%02x", repHdr[1])
	}

	bndTarget, err := novaproxy.ReadTarget(conn)
	if err != nil {
		conn.Close()
		t.Fatalf("ReadTarget bound address: %v", err)
	}

	return conn, bndTarget
}

func handleTestServerStream(stream net.Conn) {
	defer stream.Close()

	var typeBuf [1]byte
	if _, err := io.ReadFull(stream, typeBuf[:]); err != nil {
		return
	}

	switch typeBuf[0] {
	case novaproxy.StreamTypeTCP:
		target, err := novaproxy.ReadTarget(stream)
		if err != nil {
			return
		}
		targetConn, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			return
		}
		defer targetConn.Close()
		_ = novaproxy.Relay(stream, targetConn)

	case novaproxy.StreamTypeUDP:
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return
		}
		defer udpConn.Close()

		var mu sync.RWMutex
		resolvedAddrs := make(map[string]*net.UDPAddr)

		resolveTarget := func(target string) (*net.UDPAddr, error) {
			mu.RLock()
			addr, ok := resolvedAddrs[target]
			mu.RUnlock()
			if ok {
				return addr, nil
			}
			resolved, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				return nil, err
			}
			mu.Lock()
			resolvedAddrs[target] = resolved
			mu.Unlock()
			return resolved, nil
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				target, payload, err := novaproxy.ReadUDPPacket(stream)
				if err != nil {
					return
				}
				dstAddr, err := resolveTarget(target)
				if err != nil {
					continue
				}
				_, _ = udpConn.WriteToUDP(payload, dstAddr)
			}
		}()

		go func() {
			buf := make([]byte, 65535)
			for {
				select {
				case <-done:
					return
				default:
				}
				_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, srcAddr, err := udpConn.ReadFromUDP(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					return
				}
				if err := novaproxy.WriteUDPPacket(stream, srcAddr.String(), buf[:n]); err != nil {
					return
				}
			}
		}()

		<-done
	}
}
