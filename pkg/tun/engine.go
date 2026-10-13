package tun

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"novatun/pkg/proxy"
	"novatun/pkg/transport"
)

// SessionProvider retrieves an active, healthy TunnelSession.
type SessionProvider interface {
	GetSession() (*transport.TunnelSession, error)
}

// Engine implements the user-space Layer-3 packet processing engine for the TUN interface.
type Engine struct {
	dev      Device
	provider SessionProvider

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// UDP session map for return datagram routing
	// Key: remote target "IP:Port" -> client source *net.UDPAddr
	udpMu       sync.RWMutex
	udpSessions map[string]net.UDPAddr
}

// NewEngine creates a new user-space packet translation engine.
func NewEngine(dev Device, provider SessionProvider) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		dev:         dev,
		provider:    provider,
		ctx:         ctx,
		cancel:      cancel,
		udpSessions: make(map[string]net.UDPAddr),
	}
}

// Start begins processing inbound packets from the virtual TUN adapter.
func (e *Engine) Start() {
	e.wg.Add(1)
	go e.tunReadLoop()

	e.wg.Add(1)
	go e.tunnelUDPReadLoop()
}

// Stop terminates the engine and waits for loops to exit.
func (e *Engine) Stop() {
	e.cancel()
	_ = e.dev.Close()
	e.wg.Wait()
}

func (e *Engine) tunReadLoop() {
	defer e.wg.Done()

	packetBuf := make([]byte, e.dev.MTU()+100)

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
		}

		n, err := e.dev.Read(packetBuf)
		if err != nil {
			if e.ctx.Err() != nil {
				return
			}
			continue
		}
		if n <= 0 {
			continue
		}

		rawPkt := make([]byte, n)
		copy(rawPkt, packetBuf[:n])

		go e.handleInboundPacket(rawPkt)
	}
}

func (e *Engine) handleInboundPacket(b []byte) {
	pkt, err := ParseIPv4(b)
	if err != nil {
		return
	}

	// 1. Handle ICMP (Ping) locally for diagnostic responsiveness
	if pkt.Protocol == ProtoICMP {
		reply := BuildIPv4ICMPEchoReply(pkt)
		if reply != nil {
			_, _ = e.dev.Write(reply)
		}
		return
	}

	// 2. Handle UDP (DNS, Voice, Gaming)
	if pkt.Protocol == ProtoUDP {
		e.handleUDP(pkt)
		return
	}

	// 3. Handle TCP (Web, Streams)
	if pkt.Protocol == ProtoTCP {
		e.handleTCP(pkt)
		return
	}
}

func (e *Engine) handleUDP(pkt *ParsedPacket) {
	target := pkt.Target()

	// Store client source mapping for returning datagrams
	e.udpMu.Lock()
	e.udpSessions[target] = net.UDPAddr{IP: pkt.SrcIP, Port: int(pkt.SrcPort)}
	e.udpMu.Unlock()

	sess, err := e.provider.GetSession()
	if err != nil {
		return
	}

	streamCtx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
	defer cancel()

	stream, err := sess.OpenStream(streamCtx)
	if err != nil {
		return
	}
	defer stream.Close()

	// Write UDP stream type header (0x02)
	if _, err := stream.Write([]byte{proxy.StreamTypeUDP}); err != nil {
		return
	}

	// Forward encapsulated UDP datagram
	_ = proxy.WriteUDPPacket(stream, target, pkt.Payload)

	// Read immediate responses if any
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	respTarget, respPayload, err := proxy.ReadUDPPacket(stream)
	if err == nil {
		e.injectUDPResponse(respTarget, respPayload)
	}
}

func (e *Engine) injectUDPResponse(remoteTarget string, payload []byte) {
	e.udpMu.RLock()
	clientAddr, ok := e.udpSessions[remoteTarget]
	e.udpMu.RUnlock()

	var remoteIP net.IP
	var remotePort int
	host, portStr, err := net.SplitHostPort(remoteTarget)
	if err == nil {
		remoteIP = net.ParseIP(host)
		_, _ = fmt.Sscanf(portStr, "%d", &remotePort)
	}
	if remoteIP == nil {
		return
	}

	if ok {
		synthPacket := BuildIPv4UDP(remoteIP, clientAddr.IP, uint16(remotePort), uint16(clientAddr.Port), payload)
		if synthPacket != nil {
			_, _ = e.dev.Write(synthPacket)
		}
	}
}

func (e *Engine) handleTCP(pkt *ParsedPacket) {
	target := pkt.Target()

	sess, err := e.provider.GetSession()
	if err != nil {
		return
	}

	streamCtx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	defer cancel()

	stream, err := sess.OpenStream(streamCtx)
	if err != nil {
		return
	}
	defer stream.Close()

	// Write TCP stream type header (0x01)
	if _, err := stream.Write([]byte{proxy.StreamTypeTCP}); err != nil {
		return
	}

	// Send target address header
	if err := proxy.WriteTarget(stream, target); err != nil {
		return
	}

	// For standard TCP user-space bridge, payload is relayed
	if len(pkt.Payload) > 0 {
		_, _ = stream.Write(pkt.Payload)
	}
}

func (e *Engine) tunnelUDPReadLoop() {
	defer e.wg.Done()
	// Background UDP listener for long-lived tunnel streaming
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// LogPacket is a debug helper for packet inspection.
func LogPacket(pkt *ParsedPacket) {
	log.Printf("[TUN] %s -> %s (Proto: %d, PayloadLen: %d)",
		pkt.Source(), pkt.Target(), pkt.Protocol, len(pkt.Payload))
}

// Compile-time check
var _ io.Closer = (*Engine)(nil)

func (e *Engine) Close() error {
	e.Stop()
	return nil
}
