package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const (
	maxRedirects      = 10
	maxHeaderBytes    = 64 << 10
	maxRequestHeaders = 64 << 10
)

// schemeTransport dispatches by URL scheme to separate HTTP and HTTPS
// transports. It is the only transport the internal client uses.
type schemeTransport struct {
	http  *http.Transport
	https *http.Transport
}

func (t *schemeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, ErrDenied
	}
	switch req.URL.Scheme {
	case "http":
		return t.http.RoundTrip(req)
	case "https":
		return t.https.RoundTrip(req)
	}
	return nil, ErrDenied
}

func (p *Policy) newTransport(scheme string) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            func(ctx context.Context, _, addr string) (net.Conn, error) { return p.dialAddr(ctx, scheme, addr) },
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxResponseHeaderBytes: maxHeaderBytes,
		MaxIdleConns:           0,
	}
}

// dialAddr converts a stdlib host:port address into an authorized target
// carrying the exact scheme of the transport and dials it through the policy.
func (p *Policy) dialAddr(ctx context.Context, scheme, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, ErrDenied
	}
	if _, err := strconv.ParseUint(portStr, 10, 16); err != nil {
		return nil, ErrDenied
	}
	t, err := p.authorize(&url.URL{Scheme: scheme, Host: net.JoinHostPort(host, portStr)})
	if err != nil {
		return nil, err
	}
	return p.dial(ctx, t)
}

func (p *Policy) initHTTP() {
	p.httpClient = http.Client{
		Transport: &schemeTransport{
			http:  p.newTransport("http"),
			https: p.newTransport("https"),
		},
	}
}

func validMethod(m string) bool {
	if m == "" {
		return true
	}
	for i := range len(m) {
		c := m[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	switch strings.ToUpper(m) {
	case "CONNECT", "TRACE":
		return false
	}
	return true
}

func validRequest(req *http.Request) bool {
	if req == nil || req.URL == nil || req.RequestURI != "" || !validMethod(req.Method) {
		return false
	}
	u := req.URL
	if u.User != nil || u.Opaque != "" || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if req.Host != "" && req.Host != u.Host {
		return false
	}
	if len(req.Trailer) > 0 || len(req.TransferEncoding) > 0 {
		return false
	}
	size := 0
	for k, vs := range req.Header {
		switch strings.ToLower(k) {
		case "host", "upgrade", "proxy-authorization", "proxy-connection", "proxy-authenticate", "transfer-encoding":
			return false
		}
		size += len(k)
		for _, v := range vs {
			size += len(v)
			if strings.Contains(strings.ToLower(v), "upgrade") && strings.EqualFold(k, "Connection") {
				return false
			}
		}
		if size > maxRequestHeaders {
			return false
		}
	}
	return true
}

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// mapErr reduces any transport error to a value-free sentinel.
func mapErr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	switch {
	case errors.Is(err, ErrDenied):
		return ErrDenied
	case errors.Is(err, ErrResolve):
		return ErrResolve
	case errors.Is(err, ErrConnect):
		return ErrConnect
	case errors.Is(err, ErrTooLarge):
		return ErrTooLarge
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	}
	var cv *tls.CertificateVerificationError
	var al tls.AlertError
	var rh tls.RecordHeaderError
	if errors.As(err, &cv) || errors.As(err, &al) || errors.As(err, &rh) {
		return ErrConnect
	}
	return ErrResponse
}

// authority renders the canonical Host / TLS name for an authorized target:
// bracketed IPv6, port only when it differs from the scheme default.
func (t target) authority() string {
	host := t.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if t.port == defaultPort(t.scheme) {
		return host
	}
	return host + ":" + strconv.FormatUint(uint64(t.port), 10)
}

// Do sends req under the policy. Only http and https are accepted; redirects
// are followed only within the same origin.
func (p *Policy) Do(req *http.Request) (*http.Response, error) {
	if p == nil || p.httpClient.Transport == nil || p.limits.Timeout <= 0 || p.limits.MaxBodyBytes <= 0 {
		return nil, ErrDenied
	}
	if !validRequest(req) || httptrace.ContextClientTrace(req.Context()) != nil {
		if req != nil && req.Body != nil {
			req.Body.Close()
		}
		return nil, ErrDenied
	}
	origin, err := p.authorize(req.URL)
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}

	ctx, cancel := context.WithTimeout(req.Context(), p.limits.Timeout)
	cur := req.Clone(ctx)
	cur.Close = true
	cur.Host = ""
	cur.URL.Scheme = origin.scheme
	cur.URL.Host = origin.authority()
	if cur.Method == "" {
		cur.Method = http.MethodGet
	}
	if cur.Header == nil {
		cur.Header = http.Header{}
	}

	for hops := 0; ; hops++ {
		resp, err := p.httpClient.Transport.RoundTrip(cur)
		if err != nil {
			// Map before cancel: cancel would turn every error into Canceled.
			mapped := mapErr(ctx, err)
			cancel()
			return nil, mapped
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			resp.Body.Close()
			cancel()
			return nil, ErrDenied
		}
		if !isRedirect(resp.StatusCode) || resp.Header.Get("Location") == "" {
			if hops == 0 {
				resp.Request = req
			}
			return p.wrapResponse(ctx, cancel, resp, cur.Method)
		}

		next, err := cur.URL.Parse(resp.Header.Get("Location"))
		resp.Body.Close()
		if err != nil {
			cancel()
			return nil, ErrResponse
		}
		if hops >= maxRedirects || next.User != nil || next.Opaque != "" ||
			(next.Scheme != "http" && next.Scheme != "https") {
			cancel()
			return nil, ErrDenied
		}
		nt, err := p.authorize(next)
		if err != nil || nt != origin {
			cancel()
			return nil, ErrDenied
		}
		next.Scheme = nt.scheme
		next.Host = nt.authority()

		nreq := cur.Clone(ctx)
		nreq.URL = next
		nreq.Host = ""
		switch resp.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
			if nreq.Method != http.MethodHead {
				nreq.Method = http.MethodGet
			}
			nreq.Body, nreq.GetBody, nreq.ContentLength = nil, nil, 0
			nreq.Header.Del("Content-Length")
			nreq.Header.Del("Content-Type")
		default:
			if cur.Body != nil && cur.Body != http.NoBody {
				if cur.GetBody == nil {
					cancel()
					return nil, ErrDenied
				}
				b, err := cur.GetBody()
				if err != nil {
					cancel()
					return nil, ErrDenied
				}
				nreq.Body = b
			}
		}
		cur = nreq
	}
}

// bodyless reports responses that carry no body regardless of any length
// metadata (HEAD, 1xx, 204, 304).
func bodyless(method string, status int) bool {
	return method == http.MethodHead || status/100 == 1 ||
		status == http.StatusNoContent || status == http.StatusNotModified
}

func (p *Policy) wrapResponse(ctx context.Context, cancel context.CancelFunc, resp *http.Response, method string) (*http.Response, error) {
	max := p.limits.MaxBodyBytes
	if resp.ContentLength > max && !bodyless(method, resp.StatusCode) {
		resp.Body.Close()
		cancel()
		return nil, ErrTooLarge
	}
	resp.Body = &limitedBody{ctx: ctx, rc: resp.Body, remaining: max, cancel: cancel}
	resp.Uncompressed = false
	return resp, nil
}

// limitedBody enforces the body limit and total deadline, and hides raw
// transport errors. Read is not safe for concurrent use; Close may be called
// concurrently with Read and only touches the once-guarded cleanup.
type limitedBody struct {
	ctx       context.Context
	rc        io.ReadCloser
	remaining int64
	cancel    context.CancelFunc
	err       error
	once      sync.Once
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining == 0 {
		// Limit reached: probe a single byte into private scratch so the
		// caller never receives any excess.
		var scratch [1]byte
		n, err := b.rc.Read(scratch[:])
		if n > 0 {
			b.err = ErrTooLarge
			b.finish()
			return 0, b.err
		}
		return 0, b.afterRead(err)
	}
	want := int64(len(p))
	if want > b.remaining {
		want = b.remaining
	}
	n, err := b.rc.Read(p[:want])
	b.remaining -= int64(n)
	if err != nil {
		return n, b.afterRead(err)
	}
	if cerr := b.ctx.Err(); cerr != nil {
		b.err = cerr
		b.finish()
		return n, b.err
	}
	return n, nil
}

// afterRead records a terminal error (nil means keep going).
func (b *limitedBody) afterRead(err error) error {
	if err == nil {
		if cerr := b.ctx.Err(); cerr != nil {
			b.err = cerr
			b.finish()
			return b.err
		}
		return nil
	}
	if err == io.EOF {
		b.err = io.EOF
	} else {
		b.err = mapErr(b.ctx, err)
	}
	b.finish()
	return b.err
}

func (b *limitedBody) finish() {
	b.once.Do(func() {
		b.rc.Close()
		b.cancel()
	})
}

func (b *limitedBody) Close() error {
	b.finish()
	return nil
}
