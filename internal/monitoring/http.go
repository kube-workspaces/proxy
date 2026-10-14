package monitoring

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Writer preserves upgrades/streaming. Upgraded bytes include WS framing, not
// TCP/IP overhead. HTTP counts bodies, after any response rewriting.
type Writer struct {
	http.ResponseWriter
	Session     *Session
	AutoUpgrade bool
	status      int
}

func (w *Writer) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *Writer) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *Writer) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(p)
	w.Session.Add(false, n)
	return n, err
}
func (w *Writer) Flush() {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *Writer) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	if w.AutoUpgrade {
		w.Session.Establish("")
	}
	wrapped := &countConn{Conn: c, session: w.Session}
	w.Session.BindClose(wrapped.Close)
	n := rw.Reader.Buffered()
	pending := make([]byte, n)
	_, _ = io.ReadFull(rw.Reader, pending)
	reader := bufio.NewReader(io.MultiReader(&countReader{Reader: bytes.NewReader(pending), session: w.Session}, wrapped))
	if n > 0 {
		_, _ = reader.Peek(n)
	}
	return wrapped, bufio.NewReadWriter(reader, rw.Writer), nil
}

type countReader struct {
	io.Reader
	session *Session
}

func (r *countReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	r.session.Add(true, n)
	return n, e
}

type countConn struct {
	net.Conn
	session *Session
}

func (c *countConn) Close() error { c.session.End(); return c.Conn.Close() }

func (c *countConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.session.Add(true, n)
	return n, e
}
func (c *countConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.session.Add(false, n)
	return n, e
}
func PrivateHandler(r *Registry, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /snapshot", r.ServeSnapshot)
	mux.HandleFunc("GET /metrics", r.ServeMetrics)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if token == "" || subtle.ConstantTimeCompare([]byte(req.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "monitoring authentication required", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, req)
	})
}
func Listen(ctx context.Context, r *Registry, addr, token string) error {
	if token == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("monitoring listener: %w", err)
	}
	srv := &http.Server{Handler: PrivateHandler(r, token), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	go func() { _ = srv.Serve(ln) }()
	return nil
}
