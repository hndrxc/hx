package tlstrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

type tlsMaterialCert struct {
	der  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var tlsMaterialEpoch = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func tlsMaterialIssue(t *testing.T, tmpl *x509.Certificate, parent *tlsMaterialCert) *tlsMaterialCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl.SerialNumber = serial
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = tlsMaterialEpoch.Add(-time.Hour)
		tmpl.NotAfter = tlsMaterialEpoch.Add(48 * time.Hour)
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tlsMaterialCert{der: der, cert: cert, key: key}
}

func tlsMaterialCA(t *testing.T, name string, parent *tlsMaterialCert) *tlsMaterialCert {
	return tlsMaterialIssue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, parent)
}

func tlsMaterialLeaf(t *testing.T, parent *tlsMaterialCert, host string) *tlsMaterialCert {
	return tlsMaterialIssue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "leaf"},
		DNSNames:    []string{host},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, parent)
}

func tlsMaterialSelfSigned(t *testing.T, host string) *tlsMaterialCert {
	return tlsMaterialIssue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "self"},
		DNSNames:              []string{host},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, nil)
}

var tlsMaterialOrigin = Origin{Scheme: "https", Host: "svc.internal", Port: 443}

func tlsMaterialHandshake(t *testing.T, cfg *tls.Config, server *tlsMaterialCert, chain ...*tlsMaterialCert) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	ders := [][]byte{server.der}
	for _, c := range chain {
		ders = append(ders, c.der)
	}
	deadline := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(deadline)
		srv := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{{Certificate: ders, PrivateKey: server.key}}})
		_ = srv.HandshakeContext(ctx)
	}()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = raw.SetDeadline(deadline)
	herr := tls.Client(raw, cfg).HandshakeContext(ctx)
	raw.Close()
	ln.Close()
	<-srvDone
	return herr
}

func tlsMaterialClock(at time.Time) func() time.Time { return func() time.Time { return at } }

func tlsMaterialPin(t *testing.T, c *tlsMaterialCert) Pin {
	return spkiPin(c.cert)
}

func TestTLSMaterialPrivateCA(t *testing.T) {
	ca := tlsMaterialCA(t, "ca", nil)
	leaf := tlsMaterialLeaf(t, ca, "svc.internal")
	cand := Candidate{Mode: PrivateCA, Certificates: [][]byte{ca.der}}
	cfg, err := configFor(tlsMaterialOrigin, cand, nil, time.Time{}, tlsMaterialClock(tlsMaterialEpoch), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.InsecureSkipVerify {
		t.Fatal("weak defaults")
	}
	if err := tlsMaterialHandshake(t, cfg, leaf); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	wrong := tlsMaterialLeaf(t, ca, "other.internal")
	if err := tlsMaterialHandshake(t, cfg, wrong); err == nil {
		t.Fatal("wrong host accepted")
	}
	late, _ := configFor(tlsMaterialOrigin, cand, nil, time.Time{}, tlsMaterialClock(tlsMaterialEpoch.Add(100*time.Hour)), nil)
	if err := tlsMaterialHandshake(t, late, leaf); err == nil {
		t.Fatal("expired accepted")
	}
	otherCA := tlsMaterialCA(t, "other", nil)
	if err := tlsMaterialHandshake(t, cfg, tlsMaterialLeaf(t, otherCA, "svc.internal")); err == nil {
		t.Fatal("untrusted CA accepted")
	}
}

func TestTLSMaterialLeafPinOnCA(t *testing.T) {
	ca := tlsMaterialCA(t, "ca", nil)
	leaf := tlsMaterialLeaf(t, ca, "svc.internal")
	other := tlsMaterialLeaf(t, ca, "svc.internal")
	mism := 0
	cand := Candidate{Mode: PrivateCA, Certificates: [][]byte{ca.der}, LeafPin: tlsMaterialPin(t, leaf)}
	cfg, err := configFor(tlsMaterialOrigin, cand, nil, time.Time{}, tlsMaterialClock(tlsMaterialEpoch), func() error { mism++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := tlsMaterialHandshake(t, cfg, leaf); err != nil {
		t.Fatal(err)
	}
	if err := tlsMaterialHandshake(t, cfg, other); !errors.Is(err, ErrPinMismatch) || mism != 1 {
		t.Fatalf("err=%v mism=%d", err, mism)
	}
}

func TestTLSMaterialPinnedLeaf(t *testing.T) {
	self := tlsMaterialSelfSigned(t, "svc.internal")
	cand := Candidate{Mode: PinnedLeaf, Certificates: [][]byte{self.der}}
	cfg, err := configFor(tlsMaterialOrigin, cand, nil, time.Time{}, tlsMaterialClock(tlsMaterialEpoch), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlsMaterialHandshake(t, cfg, self); err != nil {
		t.Fatal(err)
	}
	if err := tlsMaterialHandshake(t, cfg, tlsMaterialSelfSigned(t, "svc.internal")); err == nil {
		t.Fatal("different self-signed accepted")
	}
	ca := tlsMaterialCA(t, "ca", nil)
	signed := tlsMaterialLeaf(t, ca, "svc.internal")
	if err := validateMaterial(tlsMaterialOrigin, Candidate{Mode: PinnedLeaf, Certificates: [][]byte{signed.der}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-self-signed: %v", err)
	}
	wrongSAN := tlsMaterialSelfSigned(t, "other.internal")
	if err := validateMaterial(tlsMaterialOrigin, Candidate{Mode: PinnedLeaf, Certificates: [][]byte{wrongSAN.der}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong SAN: %v", err)
	}
}

func TestTLSMaterialStructural(t *testing.T) {
	ca := tlsMaterialCA(t, "ca", nil)
	leaf := tlsMaterialLeaf(t, ca, "svc.internal")
	if err := validateMaterial(tlsMaterialOrigin, Candidate{Mode: PrivateCA, Certificates: [][]byte{leaf.der}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-CA anchor: %v", err)
	}
	noSign := tlsMaterialIssue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "x"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
	}, nil)
	if err := validateMaterial(tlsMaterialOrigin, Candidate{Mode: PrivateCA, Certificates: [][]byte{noSign.der}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no certsign: %v", err)
	}
	bad := []Candidate{
		{Mode: PrivateCA},
		{Mode: "x", Certificates: [][]byte{ca.der}},
		{Mode: PrivateCA, Certificates: [][]byte{append(append([]byte{}, ca.der...), 0)}},
		{Mode: PrivateCA, Certificates: [][]byte{ca.der, ca.der}},
		{Mode: PrivateCA, Certificates: [][]byte{make([]byte, maxDERLen+1)}},
	}
	for i, c := range bad {
		if err := validateMaterial(tlsMaterialOrigin, c); !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	for _, o := range []Origin{
		{"http", "svc.internal", 443}, {"https", "Svc.internal", 443}, {"https", "svc.internal.", 443},
		{"https", "svc.internal", 0}, {"https", "", 443}, {"https", "::FFFF:1.2.3.4", 443}, {"https", "fe80::1%eth0", 443},
	} {
		if validateOrigin(o) {
			t.Fatalf("accepted %+v", o)
		}
	}
	for _, o := range []Origin{{"tls", "10.0.0.1", 1}, {"wss", "::1", 9}, {"https", "a-b.c", 443}} {
		if !validateOrigin(o) {
			t.Fatalf("rejected %+v", o)
		}
	}
}

func TestTLSMaterialApprovalPins(t *testing.T) {
	ca := tlsMaterialCA(t, "ca", nil)
	leaf := tlsMaterialLeaf(t, ca, "svc.internal")
	now := tlsMaterialEpoch
	cand := Candidate{Mode: PrivateCA, Certificates: [][]byte{ca.der}, LeafPin: tlsMaterialPin(t, leaf)}
	pins, err := Discover(cand)
	if err != nil || len(pins) != 1 || pins[0] != tlsMaterialPin(t, ca) {
		t.Fatalf("discover: %v %v", pins, err)
	}
	good := []Pin{pins[0], cand.LeafPin}
	if err := validateCandidate(tlsMaterialOrigin, cand, good, now); err != nil {
		t.Fatal(err)
	}
	if err := validateCandidate(tlsMaterialOrigin, cand, pins, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing leaf witness: %v", err)
	}
	if err := validateCandidate(tlsMaterialOrigin, cand, []Pin{good[1], good[0]}, now); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("order: %v", err)
	}
	if err := validateCandidate(tlsMaterialOrigin, cand, []Pin{{}, good[1]}, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero: %v", err)
	}
	if err := validateCandidate(tlsMaterialOrigin, cand, good, now.Add(100*time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired: %v", err)
	}
	if err := validateCandidate(tlsMaterialOrigin, cand, good, now.Add(-100*time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("not yet valid: %v", err)
	}
}

func TestTLSMaterialNoMixAndMatch(t *testing.T) {
	caA := tlsMaterialCA(t, "a", nil)
	caB := tlsMaterialCA(t, "b", nil)
	leafA := tlsMaterialLeaf(t, caA, "svc.internal") // chains to A
	leafB := tlsMaterialLeaf(t, caB, "svc.internal")
	// Record A pins leafB's key; record B pins leafA's key: each half matches
	// something the server presents, but never on the same record.
	cur := Candidate{Mode: PrivateCA, Certificates: [][]byte{caA.der}, LeafPin: tlsMaterialPin(t, leafB)}
	nxt := Candidate{Mode: PrivateCA, Certificates: [][]byte{caB.der}, LeafPin: tlsMaterialPin(t, leafA)}
	until := tlsMaterialEpoch.Add(time.Hour)
	cfg, err := configFor(tlsMaterialOrigin, cur, &nxt, until, tlsMaterialClock(tlsMaterialEpoch), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlsMaterialHandshake(t, cfg, leafA); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("leafA: %v", err)
	}
	if err := tlsMaterialHandshake(t, cfg, leafB); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("leafB: %v", err)
	}
}

func TestTLSMaterialOverlapCutoff(t *testing.T) {
	caA := tlsMaterialCA(t, "a", nil)
	caB := tlsMaterialCA(t, "b", nil)
	leafA := tlsMaterialLeaf(t, caA, "svc.internal")
	leafB := tlsMaterialLeaf(t, caB, "svc.internal")
	cur := Candidate{Mode: PrivateCA, Certificates: [][]byte{caA.der}}
	nxt := Candidate{Mode: PrivateCA, Certificates: [][]byte{caB.der}}
	until := tlsMaterialEpoch.Add(time.Hour)

	now := tlsMaterialEpoch
	clock := func() time.Time { return now }
	cfg, err := configFor(tlsMaterialOrigin, cur, &nxt, until, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []*tlsMaterialCert{leafA, leafB} {
		if err := tlsMaterialHandshake(t, cfg, l); err != nil {
			t.Fatalf("overlap: %v", err)
		}
	}
	// Same config object, clock passes the deadline: old root must die in the
	// handshake callback even though it is still in the root pool.
	now = until
	if err := tlsMaterialHandshake(t, cfg, leafA); err == nil {
		t.Fatal("old root accepted after overlap")
	}
	if err := tlsMaterialHandshake(t, cfg, leafB); err != nil {
		t.Fatalf("new root: %v", err)
	}
	// Fresh config after the deadline only carries the new record.
	cfg2, err := configFor(tlsMaterialOrigin, cur, &nxt, until, clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlsMaterialHandshake(t, cfg2, leafA); err == nil {
		t.Fatal("old root accepted by fresh config")
	}
	if err := tlsMaterialHandshake(t, cfg2, leafB); err != nil {
		t.Fatal(err)
	}
	if _, err := configFor(tlsMaterialOrigin, cur, &nxt, time.Time{}, clock, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero until: %v", err)
	}
}

func TestTLSMaterialMismatchCallbackError(t *testing.T) {
	ca := tlsMaterialCA(t, "ca", nil)
	leaf := tlsMaterialLeaf(t, ca, "svc.internal")
	other := tlsMaterialLeaf(t, ca, "svc.internal")
	sentinel := errors.New("audit down")
	cand := Candidate{Mode: PrivateCA, Certificates: [][]byte{ca.der}, LeafPin: tlsMaterialPin(t, leaf)}
	cfg, _ := configFor(tlsMaterialOrigin, cand, nil, time.Time{}, tlsMaterialClock(tlsMaterialEpoch), func() error { return sentinel })
	if err := tlsMaterialHandshake(t, cfg, other); !errors.Is(err, sentinel) {
		t.Fatalf("got %v", err)
	}
}
