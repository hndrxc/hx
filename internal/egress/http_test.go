package egress

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testIP = netip.MustParseAddr("10.0.0.5")

type fixture struct {
	p       *Policy
	lookups map[string]*atomic.Int32
	mu      sync.Mutex
	dials   atomic.Int32
}

func (f *fixture) lookupCount(host string) int32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.lookups[host]; ok {
		return c.Load()
	}
	return 0
}

// newFixture builds a policy authorizing scheme://host:port whose authorized
// private address is routed to the local test server listener.
func newFixture(t *testing.T, srv *httptest.Server, scheme, host string, port uint16, limits Limits) *fixture {
	t.Helper()
	p, err := New([]Destination{{Scheme: scheme, Host: host, Port: port, PrivateIPs: []netip.Addr{testIP}}}, limits)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f := &fixture{p: p, lookups: map[string]*atomic.Int32{}}
	p.lookupIP = func(_ context.Context, h string) ([]netip.Addr, error) {
		f.mu.Lock()
		c, ok := f.lookups[h]
		if !ok {
			c = new(atomic.Int32)
			f.lookups[h] = c
		}
		f.mu.Unlock()
		c.Add(1)
		return []netip.Addr{testIP}, nil
	}
	listener := srv.Listener.Addr().String()
	p.dialTCP = func(ctx context.Context, network, _ string) (net.Conn, error) {
		f.dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, listener)
	}
	return f
}

var defaultLimits = Limits{Timeout: 5 * time.Second, MaxBodyBytes: 1 << 10}

func get(t *testing.T, ctx context.Context, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestDoBasic(t *testing.T) {
	var sawAE atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAE.Store(r.Header.Get("Accept-Encoding"))
		if r.Host != "app.example" {
			http.Error(w, "bad host", 400)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		io.WriteString(w, "plain-not-gzip")
	}))
	defer srv.Close()
	f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)
	resp, err := f.p.Do(get(t, context.Background(), "http://app.example/x"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(b) != "plain-not-gzip" {
		t.Fatalf("body %q err %v", b, err)
	}
	if ae, _ := sawAE.Load().(string); ae != "" {
		t.Fatalf("unexpected Accept-Encoding %q", ae)
	}
}

func TestSameOriginRedirectRefreshesDNS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, "http://app.example/c", http.StatusMovedPermanently)
		default:
			io.WriteString(w, "done")
		}
	}))
	defer srv.Close()
	f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)
	resp, err := f.p.Do(get(t, context.Background(), "http://app.example/a"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "done" {
		t.Fatalf("body %q", b)
	}
	if n := f.dials.Load(); n != 3 {
		t.Fatalf("dials = %d, want 3 (no connection reuse)", n)
	}
	if n := f.lookupCount("app.example"); n < 3 {
		t.Fatalf("lookups = %d, want >= 3", n)
	}
}

func TestRedirectLoopBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()
	f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)
	_, err := f.p.Do(get(t, context.Background(), "http://app.example/loop"))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if n := f.dials.Load(); n > maxRedirects+1 {
		t.Fatalf("dials = %d", n)
	}
}

func TestCrossOriginRedirectDenied(t *testing.T) {
	for _, loc := range []string{
		"http://other.example/x",
		"https://app.example/x",
		"http://app.example:8080/x",
		"ws://app.example/x",
	} {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Redirect(w, r, loc, http.StatusTemporaryRedirect)
		}))
		f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)
		req, _ := http.NewRequest(http.MethodPost, "http://app.example/", strings.NewReader("secret-body"))
		req.Header.Set("Authorization", "Bearer secret-token")
		resp, err := f.p.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("%s: want ErrDenied, got %v", loc, err)
		}
		if hits.Load() != 1 || f.dials.Load() != 1 {
			t.Fatalf("%s: hits=%d dials=%d", loc, hits.Load(), f.dials.Load())
		}
		if f.lookupCount("other.example") != 0 {
			t.Fatalf("%s: lookup performed for denied host", loc)
		}
		srv.Close()
	}
}

func TestRedirectSameOriginNoReplayableBodyDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)
	req, _ := http.NewRequest(http.MethodPost, "http://app.example/", io.NopCloser(strings.NewReader("x")))
	_, err := f.p.Do(req)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestProxyEnvIgnored(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
	}))
	defer proxy.Close()
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"} {
		t.Setenv(k, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "direct")
	}))
	defer srv.Close()
	f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)
	resp, err := f.p.Do(get(t, context.Background(), "http://app.example/"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "direct" || proxyHits.Load() != 0 {
		t.Fatalf("body %q proxyHits %d", b, proxyHits.Load())
	}
}

func TestHostileRequestsDenied(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)

	mk := func(method, url string, mod func(*http.Request)) *http.Request {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if mod != nil {
			mod(req)
		}
		return req
	}
	cases := map[string]*http.Request{
		"custom host":      mk("GET", "http://app.example/", func(r *http.Request) { r.Host = "evil.example" }),
		"connect":          mk("CONNECT", "http://app.example/", nil),
		"trace":            mk("TRACE", "http://app.example/", nil),
		"bad method":       mk("GET", "http://app.example/", func(r *http.Request) { r.Method = "GE T" }),
		"upgrade":          mk("GET", "http://app.example/", func(r *http.Request) { r.Header.Set("Upgrade", "websocket") }),
		"connection":       mk("GET", "http://app.example/", func(r *http.Request) { r.Header.Set("Connection", "Upgrade") }),
		"proxy auth":       mk("GET", "http://app.example/", func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Basic c2VjcmV0") }),
		"host header":      mk("GET", "http://app.example/", func(r *http.Request) { r.Header.Set("Host", "evil.example") }),
		"userinfo":         mk("GET", "http://user:pw@app.example/", nil),
		"request uri":      mk("GET", "http://app.example/", func(r *http.Request) { r.RequestURI = "/x" }),
		"ws scheme":        mk("GET", "ws://app.example/", nil),
		"tcp scheme":       mk("GET", "tcp://app.example/", nil),
		"unlisted host":    mk("GET", "http://other.example/", nil),
		"unlisted port":    mk("GET", "http://app.example:81/", nil),
		"unlisted scheme":  mk("GET", "https://app.example/", nil),
		"ip literal":       mk("GET", "http://10.0.0.5/", nil),
		"opaque":           mk("GET", "http://app.example/", func(r *http.Request) { r.URL.Opaque = "//x/y" }),
		"empty host":       mk("GET", "http:///x", nil),
		"huge header":      mk("GET", "http://app.example/", func(r *http.Request) { r.Header.Set("X", strings.Repeat("a", maxRequestHeaders+1)) }),
		"te header":        mk("GET", "http://app.example/", func(r *http.Request) { r.Header.Set("Transfer-Encoding", "chunked") }),
		"transfer enc":     mk("GET", "http://app.example/", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }),
		"nil url":          {Method: "GET"},
		"proxy connection": mk("GET", "http://app.example/", func(r *http.Request) { r.Header.Set("Proxy-Connection", "keep-alive") }),
	}
	for name, req := range cases {
		resp, err := f.p.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s: want ErrDenied, got %v", name, err)
		}
	}
	if _, err := f.p.Do(nil); !errors.Is(err, ErrDenied) {
		t.Errorf("nil request: got %v", err)
	}
	if hits.Load() != 0 || f.dials.Load() != 0 {
		t.Fatalf("denied requests reached network: hits=%d dials=%d", hits.Load(), f.dials.Load())
	}
}

func TestZeroValuePolicy(t *testing.T) {
	var nilp *Policy
	req := get(t, context.Background(), "http://app.example/")
	if _, err := nilp.Do(req); !errors.Is(err, ErrDenied) {
		t.Fatalf("nil policy: %v", err)
	}
	var z Policy
	if _, err := z.Do(req); !errors.Is(err, ErrDenied) {
		t.Fatalf("zero policy: %v", err)
	}
}

func TestBodyLimits(t *testing.T) {
	const max = 64
	limits := Limits{Timeout: 5 * time.Second, MaxBodyBytes: max}
	payload := func(n int) string { return strings.Repeat("a", n) }
	for _, tc := range []struct {
		name    string
		n       int
		chunked bool
		wantErr error
		wantLen int
		doErr   bool
	}{
		{"exact length known", max, false, nil, max, false},
		{"over length known", max + 1, false, ErrTooLarge, 0, true},
		{"exact unknown", max, true, nil, max, false},
		{"over unknown", max + 10, true, ErrTooLarge, max, false},
		{"one over unknown", max + 1, true, ErrTooLarge, max, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.chunked {
				io.WriteString(w, payload(tc.n/2))
				w.(http.Flusher).Flush()
				io.WriteString(w, payload(tc.n-tc.n/2))
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(tc.n))
			io.WriteString(w, payload(tc.n))
		}))
		f := newFixture(t, srv, "http", "app.example", 80, limits)
		resp, err := f.p.Do(get(t, context.Background(), "http://app.example/"))
		if tc.doErr {
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("%s: Do err %v", tc.name, err)
			}
			srv.Close()
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !errors.Is(err, tc.wantErr) && err != tc.wantErr {
			t.Fatalf("%s: read err %v want %v", tc.name, err, tc.wantErr)
		}
		if len(b) != tc.wantLen {
			t.Fatalf("%s: len %d want %d", tc.name, len(b), tc.wantLen)
		}
		srv.Close()
	}
}

func TestCancellation(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err := f.p.Do(get(t, ctx, "http://app.example/"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestTimeoutCoversBody(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "start")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	f := newFixture(t, srv, "http", "app.example", 80, Limits{Timeout: 200 * time.Millisecond, MaxBodyBytes: 1 << 10})
	resp, err := f.p.Do(get(t, context.Background(), "http://app.example/"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
}

func TestErrorsAreAuditSafe(t *testing.T) {
	secrets := []string{"app.example", "10.0.0.5", "secret-token", "evil.example", "127.0.0.1", "other.example", "/hidden-path"}
	check := func(label string, err error) {
		if err == nil {
			t.Errorf("%s: expected error", label)
			return
		}
		for _, s := range secrets {
			if strings.Contains(err.Error(), s) {
				t.Errorf("%s: error leaks %q: %v", label, s, err)
			}
		}
	}

	// Connection failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)
	f.p.dialTCP = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial 10.0.0.5:80 refused app.example")
	}
	req := get(t, context.Background(), "http://app.example/hidden-path")
	req.Header.Set("Authorization", "Bearer secret-token")
	_, err := f.p.Do(req)
	check("connect", err)

	// Resolution failure.
	f.p.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("lookup app.example failed at 10.0.0.5")
	}
	_, err = f.p.Do(get(t, context.Background(), "http://app.example/hidden-path"))
	check("resolve", err)

	// Denials.
	_, err = f.p.Do(get(t, context.Background(), "http://other.example/hidden-path"))
	check("unauthorized", err)
	req = get(t, context.Background(), "http://app.example/hidden-path")
	req.Host = "evil.example"
	_, err = f.p.Do(req)
	check("host", err)
	srv.Close()

	// Malformed response.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Write([]byte("garbage 127.0.0.1 secret-token\r\n\r\n"))
		c.Close()
	}))
	defer bad.Close()
	g := newFixture(t, bad, "http", "app.example", 80, defaultLimits)
	_, err = g.p.Do(get(t, context.Background(), "http://app.example/hidden-path"))
	check("malformed", err)
	if !errors.Is(err, ErrResponse) {
		t.Errorf("malformed: want ErrResponse, got %v", err)
	}

	// Body read failure after headers.
	trunc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort"))
		c.Close()
	}))
	defer trunc.Close()
	h := newFixture(t, trunc, "http", "app.example", 80, defaultLimits)
	resp, err := h.p.Do(get(t, context.Background(), "http://app.example/hidden-path"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	check("body", err)
	if !errors.Is(err, ErrResponse) {
		t.Errorf("body: want ErrResponse, got %v", err)
	}
}

func TestResolveErrorsNotMaskedAsCanceled(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	for _, tc := range []struct {
		name   string
		lookup func(context.Context, string) ([]netip.Addr, error)
		want   error
	}{
		{"lookup failure", func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("boom") }, ErrResolve},
		{"denied answer", func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}, ErrDenied},
	} {
		f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)
		f.p.lookupIP = tc.lookup
		_, err := f.p.Do(get(t, context.Background(), "http://app.example/"))
		if !errors.Is(err, tc.want) || errors.Is(err, context.Canceled) {
			t.Fatalf("%s: got %v want %v", tc.name, err, tc.want)
		}
	}
	// A genuinely canceled context is still reported as canceled.
	f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)
	f.p.lookupIP = func(ctx context.Context, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	_, err := f.p.Do(get(t, ctx, "http://app.example/"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want Canceled, got %v", err)
	}
}

func TestClientTraceRejected(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	f := newFixture(t, srv, "http", "app.example", 80, defaultLimits)
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { t.Error("trace hook ran") },
	})
	_, err := f.p.Do(get(t, ctx, "http://app.example/"))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if f.lookupCount("app.example") != 0 || f.dials.Load() != 0 {
		t.Fatal("traced request reached resolution or dial")
	}
}

func TestCanonicalHostForwarded(t *testing.T) {
	var hosts []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		mu.Unlock()
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "http://APP.Example.:8080/next", http.StatusFound)
		}
	}))
	defer srv.Close()
	f := newFixture(t, srv, "http", "app.example", 8080, defaultLimits)
	resp, err := f.p.Do(get(t, context.Background(), "http://APP.example:8080/start"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(hosts) != 2 || hosts[0] != "app.example:8080" || hosts[1] != "app.example:8080" {
		t.Fatalf("forwarded hosts %q", hosts)
	}
}

func TestHeadWithLargeContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
	}))
	defer srv.Close()
	f := newFixture(t, srv, "http", "app.example", 80, Limits{Timeout: 5 * time.Second, MaxBodyBytes: 8})
	req := get(t, context.Background(), "http://app.example/")
	req.Method = http.MethodHead
	resp, err := f.p.Do(req)
	if err != nil {
		t.Fatalf("HEAD denied: %v", err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || len(b) != 0 {
		t.Fatalf("HEAD body %q err %v", b, err)
	}
}

func TestLimitedBodyOverflowExposesNoExtraBytes(t *testing.T) {
	// At the maximum limit a read must not overflow remaining+1.
	lb := &limitedBody{ctx: context.Background(), rc: io.NopCloser(strings.NewReader("abc")), remaining: math.MaxInt64, cancel: func() {}}
	buf := make([]byte, 8)
	n, err := lb.Read(buf)
	if n != 3 || err != nil {
		t.Fatalf("max limit read n=%d err=%v", n, err)
	}

	// Limit reached with more data pending: no excess byte is exposed.
	lb = &limitedBody{ctx: context.Background(), rc: io.NopCloser(strings.NewReader("abcdef")), remaining: 4, cancel: func() {}}
	buf = []byte("ZZZZZZZZ")
	var got []byte
	var rerr error
	for rerr == nil {
		var n int
		n, rerr = lb.Read(buf)
		got = append(got, buf[:n]...)
	}
	if string(got) != "abcd" || !errors.Is(rerr, ErrTooLarge) {
		t.Fatalf("got %q err %v", got, rerr)
	}
	if string(buf[4:]) != "ZZZZ" {
		t.Fatalf("caller buffer touched beyond limit: %q", buf)
	}

	// Exactly at the limit ends cleanly.
	lb = &limitedBody{ctx: context.Background(), rc: io.NopCloser(strings.NewReader("abcd")), remaining: 4, cancel: func() {}}
	b, err := io.ReadAll(lb)
	if err != nil || string(b) != "abcd" {
		t.Fatalf("exact: %q %v", b, err)
	}
}
