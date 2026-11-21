package egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/hndrxc/hx/internal/egress/tlstrust"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, der: der}
}

// issue signs a server leaf for dnsName valid over [notBefore, notAfter].
func (ca *testCA) issue(t *testing.T, dnsName string, notBefore, notAfter time.Time) (tls.Certificate, [32]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

func (ca *testCA) validLeaf(t *testing.T, dnsName string) (tls.Certificate, [32]byte) {
	return ca.issue(t, dnsName, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func (ca *testCA) pin() tlstrust.Pin {
	c, _ := x509.ParseCertificate(ca.der)
	return sha256.Sum256(c.RawSubjectPublicKeyInfo)
}

func startTLSServer(t *testing.T, leaf tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// storeDir returns a test-owned directory with exact mode 0700.
func storeDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "trust")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir store dir: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod store dir: %v", err)
	}
	return dir
}

func openStore(t *testing.T) *tlstrust.Store {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("trust store is Linux-only")
	}
	st, err := tlstrust.Open(storeDir(t), func(tlstrust.AuditEvent) error { return nil })
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func trustOrigin(scheme, host string) tlstrust.Origin {
	return tlstrust.Origin{Scheme: scheme, Host: host, Port: 443}
}

// approveCA approves the CA (and optional leaf pin) for the origin.
func approveCA(t *testing.T, st *tlstrust.Store, o tlstrust.Origin, ca *testCA, leafPin tlstrust.Pin) {
	t.Helper()
	oob := []tlstrust.Pin{ca.pin()}
	if leafPin != (tlstrust.Pin{}) {
		oob = append(oob, leafPin)
	}
	c := tlstrust.Candidate{Mode: tlstrust.PrivateCA, Certificates: [][]byte{ca.der}, LeafPin: leafPin}
	if err := st.Approve(o, c, oob); err != nil {
		t.Fatalf("Approve: %v", err)
	}
}

// trustPolicy builds a policy for scheme://host:443 whose authorized private
// address is routed to the local server listener.
func trustPolicy(t *testing.T, srv *httptest.Server, scheme, host string, b *tlstrust.Binding) *Policy {
	t.Helper()
	p, err := New([]Destination{{Scheme: scheme, Host: host, Port: 443, PrivateIPs: []netip.Addr{testIP}, Trust: b}}, defaultLimits)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.lookupIP = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{testIP}, nil }
	addr := srv.Listener.Addr().String()
	p.dialTCP = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	return p
}

func doHTTPS(t *testing.T, p *Policy, host string) error {
	t.Helper()
	resp, err := p.Do(get(t, context.Background(), "https://"+host+"/"))
	if err != nil {
		return err
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok" {
		t.Fatalf("body %q", b)
	}
	return nil
}

func dialWSS(t *testing.T, p *Policy, host string) error {
	t.Helper()
	u := mustURL(t, "wss://"+host+"/")
	c, err := p.Dial(context.Background(), u)
	if err != nil {
		return err
	}
	return c.Close()
}

func TestTrustAccepts(t *testing.T) {
	const host = "example.com"
	ca := newTestCA(t, "ca")
	leaf, leafPin := ca.validLeaf(t, host)
	srv := startTLSServer(t, leaf)

	for _, tc := range []struct {
		name string
		pin  tlstrust.Pin
	}{
		{"private-ca", tlstrust.Pin{}},
		{"private-ca with leaf pin", leafPin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := openStore(t)
			for _, scheme := range []string{"https", "wss"} {
				o := trustOrigin(scheme, host)
				approveCA(t, st, o, ca, tc.pin)
				p := trustPolicy(t, srv, scheme, host, st.Bind(o))
				var err error
				if scheme == "https" {
					err = doHTTPS(t, p, host)
				} else {
					err = dialWSS(t, p, host)
				}
				if err != nil {
					t.Fatalf("%s: %v", scheme, err)
				}
			}
		})
	}
}

func TestTrustRejects(t *testing.T) {
	const host = "example.com"
	ca := newTestCA(t, "ca")
	other := newTestCA(t, "other")
	good, goodPin := ca.validLeaf(t, host)
	untrusted, _ := other.validLeaf(t, host)
	expired, _ := ca.issue(t, host, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	wrongName, _ := ca.validLeaf(t, "other.example")
	changed, _ := ca.validLeaf(t, host) // same CA, different key

	cases := []struct {
		name string
		leaf tls.Certificate
		pin  tlstrust.Pin
		want error
	}{
		{"untrusted issuer", untrusted, tlstrust.Pin{}, ErrCertificate},
		{"expired", expired, tlstrust.Pin{}, ErrCertificate},
		{"wrong name", wrongName, tlstrust.Pin{}, ErrCertificate},
		{"changed leaf pin same CA", changed, goodPin, tlstrust.ErrPinMismatch},
	}
	_ = good
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := openStore(t)
			srv := startTLSServer(t, tc.leaf)
			for _, scheme := range []string{"https", "wss"} {
				o := trustOrigin(scheme, host)
				approveCA(t, st, o, ca, tc.pin)
				p := trustPolicy(t, srv, scheme, host, st.Bind(o))
				var err error
				if scheme == "https" {
					err = doHTTPS(t, p, host)
				} else {
					err = dialWSS(t, p, host)
				}
				if !errors.Is(err, tc.want) {
					t.Fatalf("%s: want %v, got %v", scheme, tc.want, err)
				}
				if tc.want == ErrCertificate && errors.Is(err, tlstrust.ErrPinMismatch) {
					t.Fatalf("%s: unexpected pin mismatch", scheme)
				}
			}
		})
	}
}

func TestTrustUnapproved(t *testing.T) {
	const host = "example.com"
	ca := newTestCA(t, "ca")
	leaf, _ := ca.validLeaf(t, host)
	srv := startTLSServer(t, leaf)
	st := openStore(t)
	for _, scheme := range []string{"https", "wss"} {
		p := trustPolicy(t, srv, scheme, host, st.Bind(trustOrigin(scheme, host)))
		var err error
		if scheme == "https" {
			err = doHTTPS(t, p, host)
		} else {
			err = dialWSS(t, p, host)
		}
		if !errors.Is(err, tlstrust.ErrUnapproved) {
			t.Fatalf("%s: want ErrUnapproved, got %v", scheme, err)
		}
	}
}

func TestTrustDestinationValidation(t *testing.T) {
	st := openStore(t)
	b := st.Bind(trustOrigin("https", "example.com"))
	d := Destination{Scheme: "https", Host: "example.com", Port: 443, Trust: b}
	if _, err := New([]Destination{d}, defaultLimits); err != nil {
		t.Fatalf("exact binding rejected: %v", err)
	}
	for name, bad := range map[string]Destination{
		"nonsecure scheme": {Scheme: "http", Host: "example.com", Port: 443, Trust: b},
		"scheme mismatch":  {Scheme: "wss", Host: "example.com", Port: 443, Trust: b},
		"host mismatch":    {Scheme: "https", Host: "other.example", Port: 443, Trust: b},
		"port mismatch":    {Scheme: "https", Host: "example.com", Port: 8443, Trust: b},
	} {
		if _, err := New([]Destination{bad}, defaultLimits); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
}

// TestDoTLSVerified checks the default (nil Trust) configuration: standard
// chain, name and validity verification with no extra roots.
func TestDoTLSVerified(t *testing.T) {
	ca := newTestCA(t, "ca")
	leaf, _ := ca.validLeaf(t, "example.com")
	srv := startTLSServer(t, leaf)
	for _, host := range []string{"example.com", "wrong.example"} {
		p := trustPolicy(t, srv, "https", host, nil)
		if err := doHTTPS(t, p, host); !errors.Is(err, ErrCertificate) || !errors.Is(err, ErrConnect) {
			t.Fatalf("%s: want ErrCertificate, got %v", host, err)
		}
		w := trustPolicy(t, srv, "wss", host, nil)
		if err := dialWSS(t, w, host); !errors.Is(err, ErrCertificate) {
			t.Fatalf("%s wss: want ErrCertificate, got %v", host, err)
		}
	}
}

// selfSignedLeaf returns a self-signed server certificate for dnsName.
func selfSignedLeaf(t *testing.T, dnsName string) (tls.Certificate, []byte, tlstrust.Pin) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, der, sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

// openAuditStore opens a store that records every audit event.
func openAuditStore(t *testing.T) (*tlstrust.Store, func() []tlstrust.AuditEvent) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("trust store is Linux-only")
	}
	var mu sync.Mutex
	var events []tlstrust.AuditEvent
	st, err := tlstrust.Open(storeDir(t), func(e tlstrust.AuditEvent) error {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, func() []tlstrust.AuditEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]tlstrust.AuditEvent(nil), events...)
	}
}

func approveLeaf(t *testing.T, st *tlstrust.Store, o tlstrust.Origin, der []byte, pin tlstrust.Pin) {
	t.Helper()
	c := tlstrust.Candidate{Mode: tlstrust.PinnedLeaf, Certificates: [][]byte{der}}
	if err := st.Approve(o, c, []tlstrust.Pin{pin}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
}

func TestTrustPinnedLeaf(t *testing.T) {
	const host = "example.com"
	approved, approvedDER, approvedPin := selfSignedLeaf(t, host)
	changed, _, _ := selfSignedLeaf(t, host) // same name, different key

	for _, scheme := range []string{"https", "wss"} {
		run := func(srv *httptest.Server, st *tlstrust.Store) error {
			o := trustOrigin(scheme, host)
			p := trustPolicy(t, srv, scheme, host, st.Bind(o))
			if scheme == "https" {
				return doHTTPS(t, p, host)
			}
			return dialWSS(t, p, host)
		}

		t.Run(scheme+" accepts approved leaf", func(t *testing.T) {
			st := openStore(t)
			approveLeaf(t, st, trustOrigin(scheme, host), approvedDER, approvedPin)
			if err := run(startTLSServer(t, approved), st); err != nil {
				t.Fatalf("approved leaf: %v", err)
			}
		})

		t.Run(scheme+" rejects changed leaf and audits", func(t *testing.T) {
			st, events := openAuditStore(t)
			o := trustOrigin(scheme, host)
			approveLeaf(t, st, o, approvedDER, approvedPin)
			err := run(startTLSServer(t, changed), st)
			if !errors.Is(err, tlstrust.ErrPinMismatch) {
				t.Fatalf("want ErrPinMismatch, got %v", err)
			}
			found := false
			for _, e := range events() {
				if e.Action == tlstrust.PinMismatch && e.Origin == o && !e.Allowed {
					found = true
				}
			}
			if !found {
				t.Fatalf("no PinMismatch audit event in %+v", events())
			}
		})
	}
}
