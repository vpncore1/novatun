package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
)

const relayBufferSize = 32 * 1024 // 32 KB buffer

var relayPool = sync.Pool{
	New: func() any {
		b := make([]byte, relayBufferSize)
		return &b
	},
}

// closeWriter is implemented by connections that support half-closing their write side.
type closeWriter interface {
	CloseWrite() error
}

// closeReader is implemented by connections that support closing their read side.
type closeReader interface {
	CloseRead() error
}

// Relay performs a high-performance bidirectional copy between c1 and c2 using pooled 32KB buffers.
// It gracefully propagates half-closes where available and ensures both connections are closed when done.
func Relay(c1, c2 net.Conn) error {
	var wg sync.WaitGroup
	wg.Add(2)

	var err1, err2 error

	// Copy from c1 to c2
	go func() {
		defer wg.Done()
		err1 = copyOneWay(c2, c1)
		// Signal EOF to c2
		if cw, ok := c2.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = c2.Close()
		}
		if cr, ok := c1.(closeReader); ok {
			_ = cr.CloseRead()
		}
	}()

	// Copy from c2 to c1
	go func() {
		defer wg.Done()
		err2 = copyOneWay(c1, c2)
		// Signal EOF to c1
		if cw, ok := c1.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = c1.Close()
		}
		if cr, ok := c2.(closeReader); ok {
			_ = cr.CloseRead()
		}
	}()

	wg.Wait()
	_ = c1.Close()
	_ = c2.Close()

	if err1 != nil && !isIgnorableError(err1) {
		return err1
	}
	if err2 != nil && !isIgnorableError(err2) {
		return err2
	}
	return nil
}

func copyOneWay(dst io.Writer, src io.Reader) error {
	bufPtr := relayPool.Get().(*[]byte)
	buf := *bufPtr
	defer func() {
		relayPool.Put(bufPtr)
	}()

	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if ew != nil {
				return ew
			}
			if nr != nw {
				return io.ErrShortWrite
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func isIgnorableError(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Err != nil && opErr.Err.Error() == "use of closed network connection" {
			return true
		}
	}
	return false
}
