package matrixaudit

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
)

// transport uses one connection per request. http.Transport's idle-connection
// diagnostics can log unsolicited response bytes; this primitive must never do
// that. net.Dialer/tls.Dialer and http.ReadResponse perform no such logging.
// There is no proxy, connection pool, automatic retry, or HTTP/2 debug logger.
type transport struct{ tls *tls.Config }

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		defer req.Body.Close()
	}
	if req.URL.Scheme != "https" {
		return nil, unavailable
	}
	addr := req.URL.Host
	if req.URL.Port() == "" {
		addr = net.JoinHostPort(req.URL.Hostname(), "443")
	}
	conn, err := (&tls.Dialer{NetDialer: &net.Dialer{}, Config: t.tls}).DialContext(req.Context(), "tcp", addr)
	if err != nil {
		return nil, unavailable
	}
	stop := context.AfterFunc(req.Context(), func() { conn.Close() })
	closeConn := func() { stop(); conn.Close() }
	if deadline, ok := req.Context().Deadline(); ok {
		if conn.SetDeadline(deadline) != nil {
			closeConn()
			return nil, unavailable
		}
	}
	// Request.Write writes origin-form and the bearer header directly to the
	// authenticated TLS connection. No environment proxy or discovery is used.
	if req.Write(conn) != nil {
		closeConn()
		return nil, unavailable
	}
	// Bound HTTP framing as well as the separately checked endpoint body.
	// This total wire cap prevents unbounded allocation in header parsing.
	limit, ok := req.Context().Value(responseLimitKey{}).(int64)
	if !ok || limit < 1 || limit > 4*1024*1024 {
		closeConn()
		return nil, unavailable
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, limit+65536)), req)
	if err != nil {
		closeConn()
		return nil, unavailable
	}
	resp.Body = &connectionBody{ReadCloser: resp.Body, closeConn: closeConn}
	resp.Request = req
	return resp, nil
}

type connectionBody struct {
	io.ReadCloser
	once      sync.Once
	closeConn func()
}

func (b *connectionBody) Close() error { b.once.Do(b.closeConn); _ = b.ReadCloser.Close(); return nil }
