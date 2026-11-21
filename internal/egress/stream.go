package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"sync/atomic"
	"time"
)

// Dial opens a raw stream to an allowed ws, wss, tcp or tls origin.
//
// Only the origin is used. For ws and wss the URL path and query are accepted
// so a later protocol layer can use them for its own request; they are never
// sent by Dial. For tcp and tls any path, query or opaque part is denied.
// Fragments and userinfo are always denied.
//
// The policy Timeout bounds lookup, connect and (for wss/tls) the TLS
// handshake, and also fixes an absolute lifetime for the returned stream,
// measured from the start of Dial. If ctx carries an earlier deadline, that
// deadline becomes the stream lifetime instead. Callers cannot extend the
// lifetime: deadlines set on the returned conn are clamped to it, and the
// underlying connection is not exposed. When the lifetime ends the underlying
// socket is closed; I/O then fails with os.ErrDeadlineExceeded.
//
// I/O errors from the returned conn are redacted: io.EOF, io.ErrUnexpectedEOF,
// net.ErrClosed and os.ErrDeadlineExceeded are preserved, anything else is
// reported as ErrConnect so no address or raw cause escapes.
//
// ctx governs only the establishment phase. Cancelling ctx after Dial has
// returned does not affect the stream; callers close it themselves, and it is
// closed at the lifetime at the latest.
//
// wss and tls use ordinary certificate verification against target.host.
func (p *Policy) Dial(ctx context.Context, u *url.URL) (net.Conn, error) {
	if u == nil || u.User != nil || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" {
		return nil, ErrDenied
	}
	secure := false
	switch u.Scheme {
	case "ws", "tcp":
	case "wss", "tls":
		secure = true
	default:
		return nil, ErrDenied
	}
	if u.Scheme == "tcp" || u.Scheme == "tls" {
		if u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery {
			return nil, ErrDenied
		}
	}
	t, err := p.authorize(u)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, p.limits.Timeout)
	defer cancel()
	lifetime, _ := ctx.Deadline()

	conn, err := p.dial(ctx, t)
	if err != nil {
		return nil, streamErr(ctx, err)
	}
	if secure {
		tc := tls.Client(conn, &tls.Config{ServerName: t.host, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrConnect
		}
		conn = tc
	}
	if err := conn.SetDeadline(lifetime); err != nil {
		_ = conn.Close()
		return nil, ErrConnect
	}
	s := &streamConn{conn: conn, lifetime: lifetime}
	s.timer = time.AfterFunc(time.Until(lifetime), func() { _ = conn.Close() })
	return s, nil
}

// streamErr reduces a dial failure to a sentinel or context error so no
// address or raw cause is revealed.
func streamErr(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, ErrDenied):
		return ErrDenied
	case errors.Is(err, ErrResolve):
		return ErrResolve
	case errors.Is(err, ErrConnect):
		return ErrConnect
	case ctx.Err() != nil:
		return ctx.Err()
	}
	return ErrConnect
}

// streamConn wraps a connection, clamping every deadline to a fixed lifetime,
// closing the socket when the lifetime ends and redacting I/O errors.
type streamConn struct {
	conn     net.Conn
	lifetime time.Time
	timer    *time.Timer
	closed   atomic.Bool
}

func (s *streamConn) clamp(t time.Time) time.Time {
	if t.IsZero() || t.After(s.lifetime) {
		return s.lifetime
	}
	return t
}

// redact maps a raw I/O error to a canonical error without addresses.
func (s *streamConn) redact(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, io.EOF):
		return io.EOF
	case errors.Is(err, io.ErrUnexpectedEOF):
		return io.ErrUnexpectedEOF
	case !s.closed.Load() && !time.Now().Before(s.lifetime):
		// Lifetime expiry, whether seen as a deadline error or as the
		// socket being closed by the lifetime timer.
		return os.ErrDeadlineExceeded
	case errors.Is(err, os.ErrDeadlineExceeded):
		return os.ErrDeadlineExceeded
	case errors.Is(err, net.ErrClosed):
		return net.ErrClosed
	}
	return ErrConnect
}

func (s *streamConn) Read(b []byte) (int, error) {
	n, err := s.conn.Read(b)
	return n, s.redact(err)
}

func (s *streamConn) Write(b []byte) (int, error) {
	n, err := s.conn.Write(b)
	return n, s.redact(err)
}

func (s *streamConn) Close() error {
	if s.closed.Swap(true) {
		return net.ErrClosed
	}
	s.timer.Stop()
	if err := s.conn.Close(); err != nil {
		return s.redact(err)
	}
	return nil
}

func (s *streamConn) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *streamConn) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

func (s *streamConn) SetDeadline(t time.Time) error {
	return s.redact(s.conn.SetDeadline(s.clamp(t)))
}

func (s *streamConn) SetReadDeadline(t time.Time) error {
	return s.redact(s.conn.SetReadDeadline(s.clamp(t)))
}

func (s *streamConn) SetWriteDeadline(t time.Time) error {
	return s.redact(s.conn.SetWriteDeadline(s.clamp(t)))
}
