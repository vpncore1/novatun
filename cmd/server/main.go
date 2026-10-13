package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"novatun/pkg/config"
	"novatun/pkg/crypto"
	"novatun/pkg/handshake"
	"novatun/pkg/proxy"
	"novatun/pkg/transport"
	"novatun/pkg/transport/camouflage"
)

func main() {
	configPath := flag.String("config", "", "Path to server JSON configuration file")
	listenAddr := flag.String("listen", "", "Server TCP listen address (e.g. :443)")
	pskStr := flag.String("psk", "", "Pre-shared key (hex or base64 32-byte key)")
	mode := flag.String("mode", "", "Transport mode: 'raw' or 'ws'")
	wsPath := flag.String("path", "", "WebSocket camouflage URL path")
	fallbackAddr := flag.String("fallback-addr", "", "Fallback web server address for unauthorized probes")
	legacyFallback := flag.String("fallback", "", "Alias for -fallback-addr")
	flag.Parse()

	// Load base config from file if provided, otherwise defaults
	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load server config: %v", err)
	}

	// CLI flags override config file settings
	if *listenAddr != "" {
		cfg.Listen = *listenAddr
	}
	if *pskStr != "" {
		cfg.PSK = *pskStr
	}
	if *mode != "" {
		cfg.Mode = *mode
	}
	if *wsPath != "" {
		cfg.Path = *wsPath
	}
	if *fallbackAddr != "" {
		cfg.FallbackAddr = *fallbackAddr
	} else if *legacyFallback != "" {
		cfg.FallbackAddr = *legacyFallback
	}

	// Environment variable fallback
	if cfg.PSK == "" && os.Getenv("NOVATUN_PSK") != "" {
		cfg.PSK = os.Getenv("NOVATUN_PSK")
	}
	if cfg.Listen == "" && os.Getenv("NOVATUN_LISTEN") != "" {
		cfg.Listen = os.Getenv("NOVATUN_LISTEN")
	}
	if cfg.FallbackAddr == "" && os.Getenv("NOVATUN_FALLBACK") != "" {
		cfg.FallbackAddr = os.Getenv("NOVATUN_FALLBACK")
	}
	if os.Getenv("NOVATUN_MODE") != "" && *mode == "" {
		cfg.Mode = os.Getenv("NOVATUN_MODE")
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	psk, err := crypto.ParsePSK(cfg.PSK)
	if err != nil {
		log.Fatalf("[FATAL] Invalid PSK: %v", err)
	}

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("[FATAL] Failed to listen on %s: %v", cfg.Listen, err)
	}
	defer listener.Close()
	log.Printf("[INFO] novatun server listening on %s (Mode: %s, TCP+UDP, PFS, Camouflage: %v)", cfg.Listen, cfg.Mode, cfg.Mode == "ws")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Printf("[INFO] Shutting down listener...")
		_ = listener.Close()
	}()

	var fbHandler *camouflage.FallbackHandler
	if cfg.Mode == "ws" {
		fbHandler = camouflage.NewFallbackHandler(cfg.Path, cfg.FallbackAddr)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				log.Printf("[INFO] Server stopped gracefully")
				return
			default:
				log.Printf("[WARN] Accept error: %v", err)
				continue
			}
		}

		go handleClient(conn, psk, cfg.Mode, fbHandler, cfg.FallbackAddr)
	}
}

func handleClient(rawConn net.Conn, psk []byte, mode string, fbHandler *camouflage.FallbackHandler, fallback string) {
	var transportConn net.Conn = rawConn

	// If WebSocket camouflage is enabled, verify HTTP Upgrade or reverse-proxy unauthorized probes
	if mode == "ws" && fbHandler != nil {
		wsConn, err := fbHandler.AcceptOrFallback(rawConn)
		if err != nil {
			// Transparently proxied to legitimate web server and closed
			return
		}
		transportConn = wsConn
	}

	// 1. Perform server handshake with anti-replay and active-probing defense
	clientCipher, serverCipher, err := handshake.ServerHandshake(transportConn, psk, handshake.DefaultClockSkew)
	if err != nil {
		if fallback != "" && mode != "ws" {
			relayFallback(transportConn, fallback)
			return
		}
		// Silent drop to eliminate DPI active-probing signatures
		_ = transportConn.Close()
		return
	}

	// 2. Encapsulate into SecureConn
	// Server writes using serverCipher (s2c) and reads using clientCipher (c2s)
	sConn := transport.NewSecureConn(transportConn, serverCipher, clientCipher)

	// 3. Start multiplexed TunnelSession
	sess, err := transport.NewServerSession(sConn, nil)
	if err != nil {
		log.Printf("[WARN] Failed to create server session from %s: %v", rawConn.RemoteAddr(), err)
		_ = sConn.Close()
		return
	}
	defer sess.Close()
	log.Printf("[INFO] Established client session from %s", rawConn.RemoteAddr())

	// 4. Accept logical streams
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			log.Printf("[INFO] Session from %s ended: %v", rawConn.RemoteAddr(), err)
			break
		}
		go handleStream(stream)
	}
}

func handleStream(stream net.Conn) {
	defer stream.Close()

	// Read stream type header (1 byte): StreamTypeTCP (0x01) or StreamTypeUDP (0x02)
	var typeBuf [1]byte
	if _, err := io.ReadFull(stream, typeBuf[:]); err != nil {
		return
	}

	switch typeBuf[0] {
	case proxy.StreamTypeTCP:
		handleTCPStream(stream)
	case proxy.StreamTypeUDP:
		handleUDPStream(stream)
	default:
		return
	}
}

func handleTCPStream(stream net.Conn) {
	target, err := proxy.ReadTarget(stream)
	if err != nil {
		log.Printf("[WARN] Failed to read stream target: %v", err)
		return
	}

	dialer := net.Dialer{Timeout: 10 * time.Second}
	targetConn, err := dialer.Dial("tcp", target)
	if err != nil {
		log.Printf("[WARN] Failed to dial local target %s: %v", target, err)
		return
	}
	defer targetConn.Close()

	_ = proxy.Relay(stream, targetConn)
}

func handleUDPStream(stream net.Conn) {
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
			target, payload, err := proxy.ReadUDPPacket(stream)
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

			_ = udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, srcAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			srcTarget := srcAddr.String()
			if err := proxy.WriteUDPPacket(stream, srcTarget, buf[:n]); err != nil {
				return
			}
		}
	}()

	<-done
}

func relayFallback(conn net.Conn, fallback string) {
	defer conn.Close()
	fbConn, err := net.DialTimeout("tcp", fallback, 5*time.Second)
	if err != nil {
		return
	}
	defer fbConn.Close()
	_ = proxy.Relay(conn, fbConn)
}
