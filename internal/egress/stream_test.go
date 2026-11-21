package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const synthIP = "8.8.4.4"

// streamPolicy builds a policy whose lookups answer synthIP. The checked
// numeric address must equal synthIP:port; only this fixture translates it to
// the loopback listener at target.
func streamPolicy(t *testing.T, d Destination, timeout time.Duration, addr *string, mu *sync.Mutex, target string) *Policy {
	t.Helper()
	p, err := New([]Destination{d}, Limits{Timeout: timeout, MaxBodyBytes: 1 << 10})
	if err != nil {
		t.Fatal(err)
	}
	p.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(synthIP)}, nil
	}
	p.dialTCP = func(ctx context.Context, network, a string) (net.Conn, error) {
		mu.Lock()
		*addr = a
		mu.Unlock()
		var nd net.Dialer
		return nd.DialContext(ctx, network, target)
	}
	return p
}

func listen(t *testing.T) (net.Listener, uint16) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, uint16(l.Addr().(*net.TCPAddr).Port)
}

func TestDialCleartextLiteralAndLifetime(t *testing.T) {
	l, port := listen(t)
	peerClosed := make(chan struct{})
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := c.Read(buf); err == nil {
			c.Write(buf)
		}
		io.Copy(io.Discard, c) // returns when the client socket closes
		close(peerClosed)
	}()
	var addr string
	var mu sync.Mutex
	d := Destination{Scheme: "tcp", Host: synthIP, Port: port}
	p := streamPolicy(t, d, 400*time.Millisecond, &addr, &mu, l.Addr().String())

	conn, err := p.Dial(context.Background(), &url.URL{Scheme: "tcp", Host: synthIP + ":" + strconv.Itoa(int(port))})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	mu.Lock()
	got := addr
	mu.Unlock()
	if got != synthIP+":"+strconv.Itoa(int(port)) {
		t.Fatalf("dial address not literal numeric: %q", got)
	}
	if _, ok := conn.(interface{ NetConn() net.Conn }); ok {
		t.Fatal("underlying conn exposed")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q %v", buf, err)
	}

	// Callers cannot extend the lifetime; the socket is closed at expiry
	// and the error is the redacted canonical deadline error.
	start := time.Now()
	conn.SetDeadline(time.Time{})
	conn.SetReadDeadline(time.Now().Add(time.Hour))
	_, err = conn.Read(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("lifetime not enforced: %v", time.Since(start))
	}
	select {
	case <-peerClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("underlying socket not closed at lifetime")
	}
	if _, err := conn.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("post-expiry write: %v", err)
	}
}

func TestStreamErrorsRedacted(t *testing.T) {
	l, port := listen(t)
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	var addr string
	var mu sync.Mutex
	d := Destination{Scheme: "tcp", Host: synthIP, Port: port}
	p := streamPolicy(t, d, 5*time.Second, &addr, &mu, l.Addr().String())
	conn, err := p.Dial(context.Background(), &url.URL{Scheme: "tcp", Host: synthIP + ":" + strconv.Itoa(int(port))})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != io.EOF {
		t.Fatalf("peer close: want io.EOF, got %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"read":  func() error { _, e := conn.Read(buf); return e }(),
		"write": func() error { _, e := conn.Write(buf); return e }(),
		"close": conn.Close(),
	} {
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s after close: want net.ErrClosed, got %v", name, err)
		}
		if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), synthIP) {
			t.Errorf("%s leaks address: %v", name, err)
		}
	}
}

func TestDialWebSocketPathAllowed(t *testing.T) {
	l, port := listen(t)
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	var addr string
	var mu sync.Mutex
	d := Destination{Scheme: "ws", Host: synthIP, Port: port}
	p := streamPolicy(t, d, time.Second, &addr, &mu, l.Addr().String())
	conn, err := p.Dial(context.Background(), &url.URL{Scheme: "ws", Host: synthIP + ":" + strconv.Itoa(int(port)), Path: "/a", RawQuery: "x=1"})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestDialDeniesMalformed(t *testing.T) {
	var addr string
	var mu sync.Mutex
	d := Destination{Scheme: "tcp", Host: synthIP, Port: 1}
	p := streamPolicy(t, d, time.Second, &addr, &mu, "127.0.0.1:1")
	for _, raw := range []string{
		"tcp://8.8.4.4:1/path",
		"tcp://8.8.4.4:1?q=1",
		"tcp://8.8.4.4:1#frag",
		"tcp://user:secret@8.8.4.4:1",
		"http://8.8.4.4:1",
		"ws://user@8.8.4.4:1/x",
		"ws://8.8.4.4:1/x#f",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.Dial(context.Background(), u)
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s: want ErrDenied, got %v", raw, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: error leaks credentials", raw)
		}
	}
	if _, err := p.Dial(context.Background(), nil); !errors.Is(err, ErrDenied) {
		t.Errorf("nil URL: %v", err)
	}
}

func TestDialRejectsUntrustedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	port := uint16(srv.Listener.Addr().(*net.TCPAddr).Port)
	var addr string
	var mu sync.Mutex
	d := Destination{Scheme: "tls", Host: synthIP, Port: port}
	p := streamPolicy(t, d, 2*time.Second, &addr, &mu, srv.Listener.Addr().String())
	conn, err := p.Dial(context.Background(), &url.URL{Scheme: "tls", Host: synthIP + ":" + strconv.Itoa(int(port))})
	if err == nil {
		conn.Close()
		t.Fatal("untrusted certificate accepted")
	}
	if !errors.Is(err, ErrConnect) {
		t.Fatalf("want ErrConnect, got %v", err)
	}
	var ce *tls.CertificateVerificationError
	if errors.As(err, &ce) || strings.Contains(err.Error(), synthIP) {
		t.Fatalf("raw cause leaked: %v", err)
	}
}

func TestDialCancellation(t *testing.T) {
	p, err := New([]Destination{{Scheme: "tcp", Host: synthIP, Port: 9}}, Limits{Timeout: 5 * time.Second, MaxBodyBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	p.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(synthIP)}, nil
	}
	p.dialTCP = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err = p.Dial(ctx, &url.URL{Scheme: "tcp", Host: synthIP + ":9"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation not prompt")
	}
}
