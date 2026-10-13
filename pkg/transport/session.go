package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

// ────────────────────────────────────────────────────────────────────────────
// Tuned yamux defaults for proxy / tunnel workloads
// ────────────────────────────────────────────────────────────────────────────

const (
	// defaultKeepAliveInterval controls how often yamux sends keepalive probes.
	// 15 s is aggressive enough to detect dead peers quickly without drowning
	// the tunnel in overhead.
	defaultKeepAliveInterval = 15 * time.Second

	// defaultMaxStreamWindow is the per-stream flow-control window.
	// 2 MiB avoids window exhaustion on bulk transfers through the tunnel
	// while keeping per-stream memory bounded.
	defaultMaxStreamWindow = 2 * 1024 * 1024

	// defaultConnectionWriteTimeout controls the maximum time a write to the
	// underlying transport may block before yamux considers it failed.
	defaultConnectionWriteTimeout = 10 * time.Second
)

// ────────────────────────────────────────────────────────────────────────────
// Errors
// ────────────────────────────────────────────────────────────────────────────

var (
	// ErrSessionClosed is returned when operating on a closed TunnelSession.
	ErrSessionClosed = errors.New("novatun/transport: session is closed")
)

// ────────────────────────────────────────────────────────────────────────────
// TunnelSession
// ────────────────────────────────────────────────────────────────────────────

// TunnelSession wraps a *yamux.Session that runs over a SecureConn, providing
// multiplexed logical streams inside a single encrypted physical connection.
type TunnelSession struct {
	sess   *yamux.Session
	sConn  *SecureConn
	closed atomic.Bool
}

// DefaultConfig returns a *yamux.Config tuned for tunnel / proxy workloads.
// The caller may further customise the returned config before passing it to
// NewClientSession or NewServerSession.
func DefaultConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = defaultKeepAliveInterval
	cfg.MaxStreamWindowSize = defaultMaxStreamWindow
	cfg.ConnectionWriteTimeout = defaultConnectionWriteTimeout
	// Discard logs by default to keep stderr clean in production
	cfg.LogOutput = io.Discard
	cfg.Logger = nil
	return cfg
}

// NewClientSession creates a client-side multiplexed tunnel session.
//
// sConn must already be an established, post-handshake SecureConn.
// If cfg is nil, DefaultConfig() is used.
func NewClientSession(sConn *SecureConn, cfg *yamux.Config) (*TunnelSession, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	} else if cfg.Logger == nil && cfg.LogOutput == nil {
		cfg.LogOutput = io.Discard
	}
	sess, err := yamux.Client(sConn, cfg)
	if err != nil {
		return nil, err
	}
	return &TunnelSession{sess: sess, sConn: sConn}, nil
}

// NewServerSession creates a server-side multiplexed tunnel session.
//
// sConn must already be an established, post-handshake SecureConn.
// If cfg is nil, DefaultConfig() is used.
func NewServerSession(sConn *SecureConn, cfg *yamux.Config) (*TunnelSession, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	} else if cfg.Logger == nil && cfg.LogOutput == nil {
		cfg.LogOutput = io.Discard
	}
	sess, err := yamux.Server(sConn, cfg)
	if err != nil {
		return nil, err
	}
	return &TunnelSession{sess: sess, sConn: sConn}, nil
}

// OpenStream opens a new logical stream through the tunnel (client side).
// The returned net.Conn can be used like any other connection.
//
// ctx controls the deadline for establishing the stream; if the underlying
// yamux session is dead or the context expires, an error is returned.
func (ts *TunnelSession) OpenStream(ctx context.Context) (net.Conn, error) {
	if ts.closed.Load() {
		return nil, ErrSessionClosed
	}

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := ts.sess.Open()
		ch <- result{s, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

// AcceptStream accepts the next logical stream from the tunnel (server side).
// It blocks until a client opens a new stream or the session is closed.
func (ts *TunnelSession) AcceptStream() (net.Conn, error) {
	if ts.closed.Load() {
		return nil, ErrSessionClosed
	}
	s, err := ts.sess.Accept()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Close shuts down the multiplexed session and the underlying secure connection.
func (ts *TunnelSession) Close() error {
	if ts.closed.Swap(true) {
		return nil // already closed
	}
	connErr := ts.sConn.Close()
	sessErr := ts.sess.Close()
	if connErr != nil {
		return connErr
	}
	return sessErr
}

// IsClosed reports whether the session has been closed.
func (ts *TunnelSession) IsClosed() bool {
	if ts.closed.Load() {
		return true
	}
	if ts.sess != nil && ts.sess.IsClosed() {
		return true
	}
	if ts.sConn != nil && ts.sConn.IsClosed() {
		return true
	}
	return false
}

// NumStreams returns the number of currently active streams.
func (ts *TunnelSession) NumStreams() int {
	return ts.sess.NumStreams()
}

// SecureConn returns the underlying encrypted connection.
func (ts *TunnelSession) SecureConn() *SecureConn {
	return ts.sConn
}
