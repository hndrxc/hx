//go:build linux && securityfoundation

package rpc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hndrxc/hx/internal/egress"
	"github.com/hndrxc/hx/internal/egress/tlstrust"
	"github.com/hndrxc/hx/internal/hub/audit"
	"github.com/hndrxc/hx/internal/hub/tlsaudit"
	"github.com/hndrxc/hx/internal/sanitize"
)

// securityProviderText is the fixed, inert, synthetic provider sample. It
// carries an OSC 52 clipboard write (payload base64 "hx-fixture"), CSI screen
// clear and color sequences and a carriage return. It is returned raw; callers
// must sanitize it before display.
const securityProviderText = "status: \x1b]52;c;aHgtZml4dHVyZQ==\x07healthy\x1b[2J\x1b[31m (synthetic)\x1b[0m\r fixture"

// securityProviderDisplay is the exact sanitize.Log and sanitize.Label result
// for securityProviderText.
const securityProviderDisplay = "status: healthy (synthetic) fixture"

const (
	secProvPath       = "/v1/synthetic-sample"
	secProvMinCredLen = 16
	secProvTimeout    = 5 * time.Second
	secProvMaxBody    = 4 << 10
)

var (
	secProvOperatorID    = audit.ID{0x53, 0x09, 1}
	secProvIntegrationID = audit.ID{0x53, 0x09, 2}
)

// secProvFixture is one ephemeral HTTPS provider on a local private IPv4
// address with protected, explicitly approved trust.
type secProvFixture struct {
	addr   netip.Addr
	port   uint16
	url    string
	policy *egress.Policy

	ca         *secProvCA
	approved   *tls.Certificate
	current    atomic.Pointer[tls.Certificate]
	handshakes atomic.Int64 // server certificate selections (TLS reached)
	requests   atomic.Int64 // HTTP requests that reached the handler
	accepted   atomic.Int64 // requests carrying the exact fixture credential

	fetchFn func(context.Context, []byte) (string, error)
}

// newSecurityProvider starts the fixture and returns a fetch bound to it. fetch
// sends cred through the real egress policy and protected trust store and
// returns the raw provider text. It fails unless the fixture accepted exactly
// one request carrying the configured credential.
func newSecurityProvider(t *testing.T, hooks audit.Hooks, fixtureCredential string) (fetch func(context.Context, []byte) (string, error)) {
	t.Helper()
	return startSecProv(t, hooks, fixtureCredential).fetch
}

func startSecProv(t *testing.T, hooks audit.Hooks, fixtureCredential string) *secProvFixture {
	t.Helper()
	cred := []byte(fixtureCredential)
	if !secProvValidCred(cred) {
		t.Fatal("security provider fixture: credential must be at least 16 printable non-space ASCII bytes")
	}

	ln, addr := secProvListen(t)
	f := &secProvFixture{addr: addr, port: uint16(ln.Addr().(*net.TCPAddr).Port)}
	f.url = "https://" + net.JoinHostPort(addr.String(), strconv.Itoa(int(f.port))) + secProvPath

	f.ca = newSecProvCA(t, "hx s09 fixture root")
	leaf := f.ca.issue(t, addr)
	f.approved = &leaf
	f.current.Store(f.approved)

	srv := &http.Server{
		Handler:           f.handler(cred),
		ReadHeaderTimeout: secProvTimeout,
		ReadTimeout:       secProvTimeout,
		WriteTimeout:      secProvTimeout,
		IdleTimeout:       secProvTimeout,
		MaxHeaderBytes:    8 << 10,
		// Handshake failures would print peer addresses; discard them.
		ErrorLog: log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				f.handshakes.Add(1)
				return f.current.Load(), nil
			},
		},
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.ServeTLS(ln, "", "")
	}()
	// Callers open the audit log before this fixture, so this cleanup runs
	// first: the server is fully stopped before the audit log closes.
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case <-served:
		case <-time.After(secProvTimeout):
			t.Error("security provider fixture: server did not stop")
		}
	})

	origin := tlstrust.Origin{Scheme: "https", Host: addr.String(), Port: f.port}
	f.policy = secProvPolicy(t, hooks, origin, f.ca, leaf, nil)

	f.fetchFn = func(ctx context.Context, credential []byte) (string, error) {
		before := f.accepted.Load()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
		if err != nil {
			return "", errors.New("security provider fixture: request construction failed")
		}
		req.Header.Set("Authorization", "Bearer "+string(credential))
		resp, err := f.policy.Do(req)
		if err != nil {
			return "", fmt.Errorf("security provider fixture: egress refused or failed: %w", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("security provider fixture: body read failed: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("security provider fixture: provider rejected request with status %d", resp.StatusCode)
		}
		if f.accepted.Load() != before+1 {
			return "", errors.New("security provider fixture: provider did not record credential acceptance")
		}
		return string(body), nil
	}
	return f
}

// fetch is assigned in startSecProv.
func (f *secProvFixture) fetch(ctx context.Context, credential []byte) (string, error) {
	return f.fetchFn(ctx, credential)
}

func secProvValidCred(cred []byte) bool {
	if len(cred) < secProvMinCredLen || len(cred) > 512 {
		return false
	}
	for _, c := range cred {
		if c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}

// handler serves the sample only to the exact local peer with the exact
// credential. Nothing request-derived is echoed or logged.
func (f *secProvFixture) handler(cred []byte) http.Handler {
	want := append([]byte("Bearer "), cred...)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		peer, err := netip.ParseAddrPort(r.RemoteAddr)
		got := []byte(r.Header.Get("Authorization"))
		ok := err == nil && peer.Addr().Unmap() == f.addr &&
			r.Method == http.MethodGet && r.URL.Path == secProvPath && r.URL.RawQuery == "" &&
			len(r.Header.Values("Authorization")) == 1 &&
			subtle.ConstantTimeCompare(got, want) == 1
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.accepted.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, securityProviderText)
	})
}

// secProvListen binds an ephemeral port on an already assigned, egress
// eligible private IPv4 address. Egress denies loopback unconditionally, so a
// non-loopback local address is required; no wildcard bind and no DNS is used.
func secProvListen(t *testing.T) (net.Listener, netip.Addr) {
	t.Helper()
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("security provider fixture: cannot enumerate local interface addresses")
	}
	var candidates []netip.Addr
	for _, a := range ifAddrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if secProvEligible(ip) && !slices.Contains(candidates, ip) {
			candidates = append(candidates, ip)
		}
	}
	slices.SortFunc(candidates, netip.Addr.Compare)
	for _, ip := range candidates {
		ln, err := net.Listen("tcp4", netip.AddrPortFrom(ip, 0).String())
		if err == nil {
			return ln, ip
		}
	}
	t.Fatal("security provider fixture: no assigned RFC1918 or CGNAT IPv4 address could be bound; " +
		"the egress policy denies loopback, so this test requires one private non-loopback interface address")
	return nil, netip.Addr{}
}

var secProvCGNAT = netip.MustParsePrefix("100.64.0.0/10")

// secProvEligible mirrors the egress private-exception class for IPv4 while
// excluding the CGNAT-hosted platform metadata address.
func secProvEligible(ip netip.Addr) bool {
	if !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip == netip.MustParseAddr("100.100.100.200") {
		return false
	}
	return ip.IsPrivate() || secProvCGNAT.Contains(ip)
}

// secProvPolicy opens a protected trust store in a private directory, records
// explicit out-of-band approval of the root and leaf SPKI through the
// production tlsaudit adapter and returns a real egress policy whose only
// trusted origin is o. extra declares additional origins under default
// verification.
func secProvPolicy(t *testing.T, hooks audit.Hooks, o tlstrust.Origin, ca *secProvCA, leaf tls.Certificate, extra []egress.Destination) *egress.Policy {
	t.Helper()
	onAudit, err := tlsaudit.New(&hooks, secProvOperatorID, secProvIntegrationID)
	if err != nil {
		t.Fatal("security provider fixture: audit adapter unavailable")
	}
	dir := filepath.Join(t.TempDir(), "trust")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal("security provider fixture: cannot create trust directory")
	}
	store, err := tlstrust.Open(dir, onAudit)
	if err != nil {
		t.Fatal("security provider fixture: cannot open trust store")
	}
	t.Cleanup(func() { _ = store.Close() })

	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal("security provider fixture: leaf parse failed")
	}
	leafPin := tlstrust.Pin(sha256.Sum256(leafCert.RawSubjectPublicKeyInfo))
	cand := tlstrust.Candidate{Mode: tlstrust.PrivateCA, Certificates: [][]byte{ca.der}, LeafPin: leafPin}
	discovered, err := tlstrust.Discover(cand)
	if err != nil || len(discovered) != 1 {
		t.Fatal("security provider fixture: trust discovery failed")
	}
	// Out-of-band pins come from the fixture's own key material, not from
	// any handshake: the root SPKI and the leaf SPKI, in that order.
	rootPin := tlstrust.Pin(sha256.Sum256(ca.cert.RawSubjectPublicKeyInfo))
	if discovered[0] != rootPin {
		t.Fatal("security provider fixture: discovered root pin differs from out-of-band pin")
	}
	if err := store.Approve(o, cand, []tlstrust.Pin{rootPin, leafPin}); err != nil {
		t.Fatal("security provider fixture: trust approval failed")
	}

	dests := append([]egress.Destination{{
		Scheme:     o.Scheme,
		Host:       o.Host,
		Port:       o.Port,
		PrivateIPs: []netip.Addr{netip.MustParseAddr(o.Host)},
		Trust:      store.Bind(o),
	}}, extra...)
	p, err := egress.New(dests, egress.Limits{Timeout: secProvTimeout, MaxBodyBytes: secProvMaxBody})
	if err != nil {
		t.Fatal("security provider fixture: egress policy rejected")
	}
	return p
}

type secProvCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newSecProvCA(t *testing.T, name string) *secProvCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("security provider fixture: key generation failed")
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal("security provider fixture: root creation failed")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("security provider fixture: root parse failed")
	}
	return &secProvCA{cert: cert, key: key, der: der}
}

// issue signs a fresh-key server leaf whose only name is the IP address ip.
func (ca *secProvCA) issue(t *testing.T, ip netip.Addr) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("security provider fixture: key generation failed")
	}
	return ca.issueWithKey(t, ip, key)
}

// issueWithKey signs a server leaf for key whose only name is the IP address ip.
func (ca *secProvCA) issueWithKey(t *testing.T, ip netip.Addr, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal("security provider fixture: serial generation failed")
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(2)),
		Subject:      pkix.Name{CommonName: "hx s09 fixture leaf"},
		IPAddresses:  []net.IP{net.IP(ip.AsSlice())},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal("security provider fixture: leaf creation failed")
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func secProvAuditLog(t *testing.T) (audit.Hooks, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal("security provider fixture: cannot create audit directory")
	}
	p := filepath.Join(dir, "audit.jsonl")
	l, err := audit.Open(p, audit.OpenOptions{})
	if err != nil {
		t.Fatal("security provider fixture: cannot open audit log")
	}
	t.Cleanup(func() { _ = l.Close() })
	return audit.NewHooks(l), p
}

func secProvCredential(t *testing.T) []byte {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal("security provider fixture: credential generation failed")
	}
	return fmt.Appendf(nil, "hx-s09-synthetic-%x", b)
}

func TestSecurityFoundationSanitization(t *testing.T) {
	for name, got := range map[string]string{
		"log":   sanitize.Log(securityProviderText).String(),
		"label": sanitize.Label(securityProviderText).String(),
	} {
		if got != securityProviderDisplay {
			t.Errorf("%s: sanitized sample differs from securityProviderDisplay", name)
		}
	}
}

func TestSecurityFoundationProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	hooks, auditPath := secProvAuditLog(t)
	cred := secProvCredential(t)
	f := startSecProv(t, hooks, string(cred))

	// Guarded happy path.
	got, err := f.fetch(ctx, cred)
	if err != nil {
		t.Fatal("happy path: guarded fetch failed")
	}
	if got != securityProviderText {
		t.Fatal("happy path: provider text differs from securityProviderText")
	}
	if f.accepted.Load() != 1 || f.requests.Load() != 1 {
		t.Fatal("happy path: provider did not accept exactly one request")
	}

	// A wrong credential reaches the handler and is refused without the sample.
	wrong := secProvCredential(t)
	if got, err := f.fetch(ctx, wrong); err == nil || got != "" {
		t.Fatal("wrong credential: fetch succeeded")
	}
	if f.accepted.Load() != 1 || f.requests.Load() != 2 {
		t.Fatal("wrong credential: provider accepted it or never saw it")
	}

	t.Run("untrusted TLS peer denied before HTTP", func(t *testing.T) {
		// Same CA, different leaf key: chain verifies, approved leaf pin does not.
		resigned := f.ca.issue(t, f.addr)
		// Unapproved CA entirely, approved SPKI and SAN preserved: only standard
		// chain verification can refuse it.
		foreign := newSecProvCA(t, "hx s09 unapproved root").issueWithKey(t, f.addr, f.approved.PrivateKey.(*ecdsa.PrivateKey))
		for _, c := range []struct {
			name string
			leaf *tls.Certificate
			want error
		}{
			{"leaf pin mismatch", &resigned, tlstrust.ErrPinMismatch},
			{"unapproved root", &foreign, egress.ErrCertificate},
		} {
			hs, requests, accepted := f.handshakes.Load(), f.requests.Load(), f.accepted.Load()
			f.current.Store(c.leaf)
			got, err := f.fetch(ctx, cred)
			f.current.Store(f.approved)
			if !errors.Is(err, c.want) || got != "" {
				t.Fatalf("%s: egress did not return the expected sentinel", c.name)
			}
			if f.handshakes.Load() == hs {
				t.Fatalf("%s: TLS was never reached", c.name)
			}
			if f.requests.Load() != requests || f.accepted.Load() != accepted {
				t.Fatalf("%s: credential reached HTTP over an untrusted TLS peer", c.name)
			}
		}
		// Same port, approved leaf restored: allowed again.
		if got, err := f.fetch(ctx, cred); err != nil || got != securityProviderText {
			t.Fatal("restored leaf: approved fetch did not return the sample")
		}
	})

	t.Run("loopback and metadata denied inside declared origins", func(t *testing.T) {
		loop, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal("cannot bind loopback canary")
		}
		var loopAccepts atomic.Int64
		accepted := make(chan struct{})
		go func() {
			defer close(accepted)
			for {
				c, err := loop.Accept()
				if err != nil {
					return
				}
				loopAccepts.Add(1)
				_ = c.Close()
			}
		}()
		loopPort := uint16(loop.Addr().(*net.TCPAddr).Port)

		hooks2, _ := secProvAuditLog(t)
		cred2 := secProvCredential(t)
		g := startSecProv(t, hooks2, string(cred2))
		origin := tlstrust.Origin{Scheme: "https", Host: g.addr.String(), Port: g.port}
		declared := []egress.Destination{
			{Scheme: "https", Host: "127.0.0.1", Port: loopPort},
			{Scheme: "http", Host: "127.0.0.1", Port: loopPort},
			{Scheme: "https", Host: "169.254.169.254"},
			{Scheme: "http", Host: "169.254.169.254"},
			{Scheme: "http", Host: "100.100.100.200"},
		}
		p := secProvPolicy(t, hooks2, origin, g.ca, *g.approved, declared)
		for i, d := range declared {
			u := url.URL{Scheme: d.Scheme, Host: d.Host, Path: secProvPath}
			if d.Port != 0 {
				u.Host = net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port)))
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				t.Fatal("declared origin: request construction failed")
			}
			req.Header.Set("Authorization", "Bearer "+string(cred2))
			resp, err := p.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !errors.Is(err, egress.ErrDenied) {
				t.Fatalf("declared %s origin %d: not denied", d.Scheme, i)
			}
		}
		_ = loop.Close()
		<-accepted
		if loopAccepts.Load() != 0 {
			t.Fatal("loopback canary received a connection")
		}
		// The same policy still reaches the approved private origin.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.url, nil)
		if err != nil {
			t.Fatal("approved origin: request construction failed")
		}
		req.Header.Set("Authorization", "Bearer "+string(cred2))
		resp, err := p.Do(req)
		if err != nil {
			t.Fatal("approved origin under scoped policy: guarded fetch failed")
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || string(body) != securityProviderText || g.accepted.Load() != 1 {
			t.Fatal("approved origin under scoped policy: unexpected result")
		}
	})

	// Every refused TLS case is audited; the server stopped (cleanup) before
	// the audit log closes, and the log is read here while still open.

	// No leakage: audit records carry no credential, address or certificate.
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal("cannot read audit log")
	}
	for name, secret := range map[string][]byte{
		"credential":       cred,
		"wrong credential": wrong,
		"address":          []byte(f.addr.String()),
		"leaf certificate": f.approved.Certificate[0],
		"root certificate": f.ca.der,
	} {
		if bytes.Contains(data, secret) {
			t.Fatalf("audit log contains the %s", name)
		}
	}
	for _, action := range []audit.Action{audit.ActionTLSTrustApproval, audit.ActionTLSPinMismatch} {
		if !bytes.Contains(data, []byte(`"`+string(action)+`"`)) {
			t.Fatalf("audit log lacks %s", action)
		}
	}
}
