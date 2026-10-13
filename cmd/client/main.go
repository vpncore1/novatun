package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	"novatun/pkg/tun"
)

// TunnelManager manages a live multiplexed tunnel session to the remote server,
// automatically reconnecting with exponential backoff if the session is severed.
type TunnelManager struct {
	serverAddr string
	psk        []byte
	mode       string
	hostHeader string
	wsPath     string

	mu      sync.RWMutex
	session *transport.TunnelSession
	closed  bool
}

func NewTunnelManager(serverAddr string, psk []byte, mode, hostHeader, wsPath string) *TunnelManager {
	if mode == "" {
		mode = "raw"
	}
	if wsPath == "" {
		wsPath = camouflage.DefaultWSPath
	}
	return &TunnelManager{
		serverAddr: serverAddr,
		psk:        psk,
		mode:       mode,
		hostHeader: hostHeader,
		wsPath:     wsPath,
	}
}

// GetSession returns an active TunnelSession, connecting if necessary.
func (tm *TunnelManager) GetSession() (*transport.TunnelSession, error) {
	tm.mu.RLock()
	if tm.closed {
		tm.mu.RUnlock()
		return nil, errors.New("novatun/client: tunnel manager is closed")
	}
	sess := tm.session
	if sess != nil && !sess.IsClosed() {
		tm.mu.RUnlock()
		return sess, nil
	}
	tm.mu.RUnlock()

	// Need to acquire write lock to establish a new session
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.closed {
		return nil, errors.New("novatun/client: tunnel manager is closed")
	}
	// Double-check under lock
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

// connect dials the server, executes the handshake, and wraps in yamux.
func (tm *TunnelManager) connect() (*transport.TunnelSession, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.Dial("tcp", tm.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("dial remote server %s: %w", tm.serverAddr, err)
	}

	var transportConn net.Conn = rawConn

	// If WebSocket HTTPS camouflage is enabled, wrap in RFC 6455 client framing
	if tm.mode == "ws" {
		host := tm.hostHeader
		if host == "" {
			host, _, _ = net.SplitHostPort(tm.serverAddr)
			if host == "" {
				host = tm.serverAddr
			}
		}
		wsConn, err := camouflage.NewClientWSConn(rawConn, host, tm.wsPath)
		if err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("websocket camouflage upgrade: %w", err)
		}
		transportConn = wsConn
	}

	// Client writes with clientCipher (c2s) and reads with serverCipher (s2c)
	clientCipher, serverCipher, err := handshake.ClientHandshake(transportConn, tm.psk)
	if err != nil {
		_ = transportConn.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	sConn := transport.NewSecureConn(transportConn, clientCipher, serverCipher)
	sess, err := transport.NewClientSession(sConn, nil)
	if err != nil {
		_ = sConn.Close()
		return nil, fmt.Errorf("create client session: %w", err)
	}

	log.Printf("[INFO] Established secure tunnel session to %s (Mode: %s)", tm.serverAddr, tm.mode)
	return sess, nil
}

// Maintain keeps the tunnel connected in the background.
func (tm *TunnelManager) Maintain(ctx context.Context) {
	backoff := 500 * time.Millisecond
	const maxBackoff = 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sess, err := tm.GetSession()
		if err != nil {
			log.Printf("[WARN] Tunnel reconnect failed: %v (retrying in %v)", err, backoff)
			select {
			case <-time.After(backoff):
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			case <-ctx.Done():
				return
			}
			continue
		}

		// Reset backoff once connected
		backoff = 500 * time.Millisecond

		// Poll periodically to verify health
		time.Sleep(1 * time.Second)
		if sess.IsClosed() {
			log.Printf("[WARN] Active tunnel session closed. Triggering reconnect...")
		}
	}
}

func (tm *TunnelManager) Close() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.closed = true
	if tm.session != nil {
		_ = tm.session.Close()
	}
}

// openStreamWithRetry opens a stream of the requested streamType over the tunnel,
// re-acquiring a fresh session if the current session was severed.
func openStreamWithRetry(ctx context.Context, tm *TunnelManager, streamType byte) (*transport.TunnelSession, net.Conn, error) {
	sess, err := tm.GetSession()
	if err != nil {
		return nil, nil, err
	}

	streamCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	stream, err := sess.OpenStream(streamCtx)
	if err != nil || sess.IsClosed() {
		_ = sess.Close()
		sess, err = tm.GetSession()
		if err != nil {
			return nil, nil, err
		}
		stream, err = sess.OpenStream(streamCtx)
		if err != nil {
			return nil, nil, err
		}
	}

	// Write 1-byte stream type header
	if _, err := stream.Write([]byte{streamType}); err != nil {
		_ = stream.Close()
		_ = sess.Close()
		sess, err = tm.GetSession()
		if err != nil {
			return nil, nil, err
		}
		stream, err = sess.OpenStream(streamCtx)
		if err != nil {
			return nil, nil, err
		}
		if _, err := stream.Write([]byte{streamType}); err != nil {
			_ = stream.Close()
			return nil, nil, err
		}
	}

	return sess, stream, nil
}
func main() {
	configPath := flag.String("config", "", "Path to client JSON configuration file")
	socksAddr := flag.String("socks", "", "Local SOCKS5 listen address (empty to disable)")
	serverAddr := flag.String("server", "", "Remote novatun server address")
	pskStr := flag.String("psk", "", "Pre-shared key (hex or base64 32-byte key)")
	mode := flag.String("mode", "", "Transport mode: 'raw' (pure DPI-resistant frames) or 'ws' (WebSocket HTTPS camouflage)")
	hostHeader := flag.String("host", "", "Host/SNI header for WebSocket camouflage (e.g. cdn.example.com)")
	wsPath := flag.String("path", "", "WebSocket camouflage URL path (e.g. /api/v1/stream)")
	enableTUN := flag.Bool("tun", false, "Enable full-tunnel OS virtual TUN VPN mode")
	tunName := flag.String("tun-name", "", "Virtual TUN adapter name")
	forwardPorts := flag.String("forward-ports", "", "Comma-separated list/ranges of ports to listen and forward to Kharej (e.g. '443,80,2053,8443')")
	flag.Parse()

	// Load base config from file if provided, otherwise defaults
	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load client config: %v", err)
	}

	// CLI flags override config file
	if *serverAddr != "" {
		cfg.Server = *serverAddr
	}
	if *pskStr != "" {
		cfg.PSK = *pskStr
	}
	if *mode != "" {
		cfg.Mode = *mode
	}
	if *hostHeader != "" {
		cfg.Host = *hostHeader
	}
	if *wsPath != "" {
		cfg.Path = *wsPath
	}
	if *socksAddr != "" {
		cfg.Socks = *socksAddr
	}
	if *forwardPorts != "" {
		cfg.ForwardPorts = *forwardPorts
	}
	// Check if -tun flag was explicitly provided on CLI
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "tun" {
			cfg.TUN = *enableTUN
		}
	})
	if *tunName != "" {
		cfg.TUNName = *tunName
	}

	// Environment variable overrides / fallbacks
	if cfg.PSK == "" && os.Getenv("NOVATUN_PSK") != "" {
		cfg.PSK = os.Getenv("NOVATUN_PSK")
	}
	if os.Getenv("NOVATUN_SERVER") != "" && *serverAddr == "" {
		cfg.Server = os.Getenv("NOVATUN_SERVER")
	}
	if os.Getenv("NOVATUN_SOCKS") != "" && *socksAddr == "" {
		cfg.Socks = os.Getenv("NOVATUN_SOCKS")
	}
	if os.Getenv("NOVATUN_MODE") != "" && *mode == "" {
		cfg.Mode = os.Getenv("NOVATUN_MODE")
	}
	if os.Getenv("NOVATUN_HOST") != "" && *hostHeader == "" {
		cfg.Host = os.Getenv("NOVATUN_HOST")
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	psk, err := crypto.ParsePSK(cfg.PSK)
	if err != nil {
		log.Fatalf("[FATAL] Invalid PSK: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tunnelMgr := NewTunnelManager(cfg.Server, psk, cfg.Mode, cfg.Host, cfg.Path)
	defer tunnelMgr.Close()

	// Start background tunnel connection maintenance loop
	go tunnelMgr.Maintain(ctx)

	// 1. Initialize Full-Tunnel Virtual TUN VPN if requested
	if cfg.TUN {
		log.Printf("[INFO] Initializing virtual TUN adapter %s...", cfg.TUNName)
		tunCfg := tun.DefaultConfig()
		tunCfg.Name = cfg.TUNName

		dev, err := tun.CreateDevice(tunCfg)
		if err != nil {
			log.Fatalf("[FATAL] Failed to create virtual TUN device %s: %v", cfg.TUNName, err)
		}
		defer dev.Close()
		log.Printf("[INFO] Created TUN device %s (IP: %s, MTU: %d)", dev.Name(), tun.DefaultLocalIPv4, dev.MTU())

		// Setup OS routing rules with routing-loop protection for server IP
		router := tun.NewRouter(cfg.Server, tun.DefaultGWIPv4, dev.Name())
		if err := router.SetupRoutes(); err != nil {
			log.Printf("[WARN] Failed to configure OS routing table: %v (run as administrator/root)", err)
		} else {
			log.Printf("[INFO] Configured system default routes through %s (bypass for %s active)", dev.Name(), cfg.Server)
			defer func() {
				log.Printf("[INFO] Restoring system routing table...")
				_ = router.RestoreRoutes()
			}()
		}

		// Start user-space packet translation engine
		engine := tun.NewEngine(dev, tunnelMgr)
		engine.Start()
		defer engine.Stop()
		log.Printf("[INFO] TUN packet forwarding engine started")
	}

	// 2. SOCKS5 Inbound Server (runs concurrently if configured)
	if cfg.Socks != "" {
		socksServer := &proxy.Server{
			TCPHandler: func(ctx context.Context, clientConn net.Conn, target string) error {
				_, stream, err := openStreamWithRetry(ctx, tunnelMgr, proxy.StreamTypeTCP)
				if err != nil {
					_ = proxy.SendReply(clientConn, proxy.ReplyNetworkUnreachable)
					return err
				}
				defer stream.Close()

				// Write target header
				if err := proxy.WriteTarget(stream, target); err != nil {
					_ = proxy.SendReply(clientConn, proxy.ReplyGeneralFailure)
					return err
				}

				// Signal SOCKS5 success
				if err := proxy.SendReply(clientConn, proxy.ReplySuccess); err != nil {
					return err
				}

				// Zero-allocation bidirectional streaming relay
				return proxy.Relay(clientConn, stream)
			},

			UDPHandler: func(ctx context.Context, clientTCPConn net.Conn, clientAddrHint string) error {
				tcpLocalAddr := clientTCPConn.LocalAddr().(*net.TCPAddr)
				udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: tcpLocalAddr.IP, Port: 0})
				if err != nil {
					_ = proxy.SendReply(clientTCPConn, proxy.ReplyGeneralFailure)
					return err
				}
				defer udpListener.Close()

				bndAddr := udpListener.LocalAddr().String()

				_, stream, err := openStreamWithRetry(ctx, tunnelMgr, proxy.StreamTypeUDP)
				if err != nil {
					_ = proxy.SendReply(clientTCPConn, proxy.ReplyNetworkUnreachable)
					return err
				}
				defer stream.Close()

				if err := proxy.SendReplyWithAddr(clientTCPConn, proxy.ReplySuccess, bndAddr); err != nil {
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

						target, payload, err := proxy.ParseSocks5UDPPacket(packetBuf[:n])
						if err != nil {
							continue
						}

						if err := proxy.WriteUDPPacket(stream, target, payload); err != nil {
							return
						}
					}
				}()

				go func() {
					for {
						target, payload, err := proxy.ReadUDPPacket(stream)
						if err != nil {
							return
						}

						socks5Packet, err := proxy.EncodeSocks5UDPPacket(target, payload)
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

		listener, err := net.Listen("tcp", cfg.Socks)
		if err != nil {
			log.Fatalf("[FATAL] Failed to listen on SOCKS5 address %s: %v", cfg.Socks, err)
		}
		defer listener.Close()
		log.Printf("[INFO] novatun SOCKS5 client running on %s -> tunnel %s (Mode: %s)", cfg.Socks, cfg.Server, cfg.Mode)

		go func() {
			<-ctx.Done()
			log.Printf("[INFO] Shutting down SOCKS5 listener...")
			_ = listener.Close()
		}()

		go func() {
			if err := socksServer.Serve(listener); err != nil {
				select {
				case <-ctx.Done():
				default:
					log.Printf("[WARN] SOCKS5 server terminated: %v", err)
				}
			}
		}()
	}

	// 3. Transparent Multi-Port Forwarding Relay (for direct x-ui / Sanaei bridge)
	if cfg.ForwardPorts != "" {
		ports, err := config.ParsePortList(cfg.ForwardPorts)
		if err != nil {
			log.Fatalf("[FATAL] Invalid forward_ports configuration: %v", err)
		}

		for _, port := range ports {
			p := port
			targetAddr := fmt.Sprintf("127.0.0.1:%d", p)

			// Start TCP Port Listener
			tcpListenAddr := fmt.Sprintf("0.0.0.0:%d", p)
			tcpLn, err := net.Listen("tcp", tcpListenAddr)
			if err != nil {
				log.Printf("[WARN] Failed to bind TCP forward port %d: %v", p, err)
			} else {
				log.Printf("[INFO] Forwarding TCP port %d -> remote Kharej %s", p, targetAddr)
				go func(ln net.Listener, target string) {
					go func() {
						<-ctx.Done()
						_ = ln.Close()
					}()

					for {
						inConn, err := ln.Accept()
						if err != nil {
							return
						}

						go func(c net.Conn) {
							defer c.Close()
							_, stream, err := openStreamWithRetry(ctx, tunnelMgr, proxy.StreamTypeTCP)
							if err != nil {
								return
							}
							defer stream.Close()

							if err := proxy.WriteTarget(stream, target); err != nil {
								return
							}
							_ = proxy.Relay(c, stream)
						}(inConn)
					}
				}(tcpLn, targetAddr)
			}

			// Start UDP Port Listener
			udpListenAddr := fmt.Sprintf("0.0.0.0:%d", p)
			udpLAddr, err := net.ResolveUDPAddr("udp", udpListenAddr)
			if err == nil {
				udpConn, err := net.ListenUDP("udp", udpLAddr)
				if err != nil {
					log.Printf("[WARN] Failed to bind UDP forward port %d: %v", p, err)
				} else {
					log.Printf("[INFO] Forwarding UDP port %d -> remote Kharej %s", p, targetAddr)
					go func(u *net.UDPConn, target string) {
						go func() {
							<-ctx.Done()
							_ = u.Close()
						}()

						// Map client remote addr to tunnel UDP stream
						var streamMu sync.Mutex
						var udpStream net.Conn
						clientAddrMap := make(map[string]time.Time)
						var clientMapMu sync.RWMutex

						ensureUDPStream := func() (net.Conn, error) {
							streamMu.Lock()
							defer streamMu.Unlock()
							if udpStream != nil {
								return udpStream, nil
							}
							_, s, err := openStreamWithRetry(ctx, tunnelMgr, proxy.StreamTypeUDP)
							if err != nil {
								return nil, err
							}
							udpStream = s

							// Reader from Kharej UDP stream back to clients
							go func(st net.Conn) {
								defer func() {
									streamMu.Lock()
									if udpStream == st {
										udpStream = nil
									}
									streamMu.Unlock()
									_ = st.Close()
								}()

								for {
									_, payload, err := proxy.ReadUDPPacket(st)
									if err != nil {
										return
									}
									// Broadcast response to active clients on this port
									clientMapMu.RLock()
									for cAddrStr := range clientAddrMap {
										if rAddr, err := net.ResolveUDPAddr("udp", cAddrStr); err == nil {
											_, _ = u.WriteToUDP(payload, rAddr)
										}
									}
									clientMapMu.RUnlock()
								}
							}(s)

							return udpStream, nil
						}

						buf := make([]byte, 65535)
						for {
							n, cAddr, err := u.ReadFromUDP(buf)
							if err != nil {
								return
							}

							clientMapMu.Lock()
							clientAddrMap[cAddr.String()] = time.Now()
							clientMapMu.Unlock()

							st, err := ensureUDPStream()
							if err != nil {
								continue
							}

							_ = proxy.WriteUDPPacket(st, target, buf[:n])
						}
					}(udpConn, targetAddr)
				}
			}
		}
	}

	<-ctx.Done()
	log.Printf("[INFO] Client stopped gracefully")
}
