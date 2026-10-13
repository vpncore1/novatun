package camouflage

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// FallbackHandler inspects initial inbound HTTP traffic on port 443 / listener.
// If it is a legitimate novatun WebSocket upgrade request matching wsPath, it completes
// the 101 Switching Protocols response and returns a ready-to-use *WSConn.
// If it is an unauthorized probe, web crawler, or scanner, it transparently proxies
// the request to fallbackAddr (or returns a benign standard HTTP 200/404 response).
type FallbackHandler struct {
	wsPath       string
	fallbackAddr string
}

// NewFallbackHandler creates an active probing defense and web camouflage router.
func NewFallbackHandler(wsPath, fallbackAddr string) *FallbackHandler {
	if wsPath == "" {
		wsPath = DefaultWSPath
	}
	return &FallbackHandler{
		wsPath:       wsPath,
		fallbackAddr: fallbackAddr,
	}
}

// AcceptOrFallback inspects conn. If the request is a valid WebSocket upgrade to wsPath,
// it completes the upgrade and returns (wsConn, nil).
// Otherwise, it transparently services or proxies the request to fallback and closes conn,
// returning (nil, ErrHandshakeFailed).
func (h *FallbackHandler) AcceptOrFallback(conn net.Conn) (*WSConn, error) {
	// Set initial read deadline to protect against slowloris attacks
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	req, err := http.ReadRequest(br)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		// Not even valid HTTP (random noise or direct raw probe)
		h.handleDirectFallback(conn, nil, nil)
		return nil, ErrHandshakeFailed
	}

	// Validate WebSocket Upgrade headers and configured camouflage path
	isUpgrade := strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
	isConnUpgrade := strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
	isMatchingPath := req.URL.Path == h.wsPath
	wsKey := req.Header.Get("Sec-WebSocket-Key")

	if isUpgrade && isConnUpgrade && isMatchingPath && wsKey != "" {
		// Valid authorized tunnel connection: complete RFC 6455 101 Switching Protocols
		acceptKey := ComputeSecWebSocketAccept(wsKey)
		resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n", acceptKey)

		if _, err := conn.Write([]byte(resp)); err != nil {
			_ = conn.Close()
			return nil, err
		}

		return NewServerWSConn(conn, br), nil
	}

	// Unauthorized probe / regular web visitor -> transparent fallback
	h.handleDirectFallback(conn, req, br)
	return nil, ErrHandshakeFailed
}

func (h *FallbackHandler) handleDirectFallback(conn net.Conn, req *http.Request, br *bufio.Reader) {
	defer conn.Close()

	if h.fallbackAddr != "" {
		// Reverse-proxy to legitimate local/remote web server
		fbConn, err := net.DialTimeout("tcp", h.fallbackAddr, 5*time.Second)
		if err == nil {
			defer fbConn.Close()
			if req != nil {
				_ = req.Write(fbConn)
			}
			// Read the response from fallback backend and write back to client
			resp, err := http.ReadResponse(bufio.NewReader(fbConn), req)
			if err == nil {
				_ = resp.Write(conn)
				return
			}
			_, _ = io.Copy(conn, fbConn)
			return
		}
	}

	// Default Benign Camouflage Response (Standard legitimate Nginx / Apache 404 or 200)
	body := "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\n"+
		"Server: nginx\r\n"+
		"Date: %s\r\n"+
		"Content-Type: text/html\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n\r\n%s",
		time.Now().UTC().Format(http.TimeFormat), len(body), body)

	_, _ = conn.Write([]byte(resp))
}

type sync_wait_group struct {
	ch chan struct{}
	n  int
}

func (s *sync_wait_group) Add(delta int) {
	if s.ch == nil {
		s.ch = make(chan struct{}, 10)
	}
	s.n += delta
}

func (s *sync_wait_group) Done() {
	s.ch <- struct{}{}
}

func (s *sync_wait_group) Wait() {
	for i := 0; i < s.n; i++ {
		<-s.ch
	}
}

// WriteBufferedRequest is a utility to dump a parsed request back to wire.
func WriteBufferedRequest(w io.Writer, req *http.Request) error {
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}
