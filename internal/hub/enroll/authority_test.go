//go:build linux

package enroll

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/hndrxc/hx/internal/secret"
)

var authTestNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func authTestRoot(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hx test root"},
		NotBefore:             authTestNow.Add(-time.Hour),
		NotAfter:              authTestNow.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der, priv
}

func authTestStaticKey(k crypto.Signer) SigningKey {
	return func(_ context.Context, fn func(crypto.Signer) error) error { return fn(k) }
}

var errAuthTestLocked = errors.New("locked")

func authTestLockedKey(context.Context, func(crypto.Signer) error) error { return errAuthTestLocked }

func authTestCSR(t *testing.T, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl == nil {
		tmpl = &x509.CertificateRequest{}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func authTestID(b byte) ID {
	var id ID
	for i := range id {
		id[i] = b
	}
	return id
}

func TestAuthorityIssueLeafProfileIgnoresCSRClaims(t *testing.T) {
	rootDER, priv := authTestRoot(t)
	a, err := NewAuthority(rootDER, authTestStaticKey(priv))
	if err != nil {
		t.Fatal(err)
	}
	evil, _ := url.Parse("urn:hx:identity:ffffffffffffffffffffffffffffffff")
	csr, err := parseCSR(authTestCSR(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "attacker"},
		DNSNames: []string{"evil.example"},
		URIs:     []*url.URL{evil},
	}))
	if err != nil {
		t.Fatal(err)
	}
	id := authTestID(0xab)
	der, err := a.issue(context.Background(), id, csr, authTestNow)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := a.verify(der, authTestNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if cert.IsCA || cert.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("bad leaf profile")
	}
	if len(cert.DNSNames) != 0 || cert.Subject.CommonName == "attacker" || len(cert.URIs) != 1 {
		t.Fatal("csr claims copied into leaf")
	}
	if cert.NotAfter.Sub(cert.NotBefore) != leafTTL || cert.SerialNumber.Sign() <= 0 {
		t.Fatal("bad validity or serial")
	}
	got, err := certificateID(cert)
	if err != nil || got != id {
		t.Fatalf("identity = %v, %v", got, err)
	}
	if _, err := a.verify(der, authTestNow.Add(25*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired err = %v", err)
	}
}

func TestAuthorityRejectsMismatchedSigner(t *testing.T) {
	rootDER, _ := authTestRoot(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	a, err := NewAuthority(rootDER, authTestStaticKey(other))
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := parseCSR(authTestCSR(t, nil))
	if _, err := a.issue(context.Background(), authTestID(1), csr, authTestNow); !errors.Is(err, ErrCertificate) {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthorityVerifyWhileLocked(t *testing.T) {
	rootDER, priv := authTestRoot(t)
	issuer, _ := NewAuthority(rootDER, authTestStaticKey(priv))
	csr, _ := parseCSR(authTestCSR(t, nil))
	der, err := issuer.issue(context.Background(), authTestID(2), csr, authTestNow)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := NewAuthority(rootDER, authTestLockedKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := locked.verify(der, authTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := locked.issue(context.Background(), authTestID(3), csr, authTestNow); !errors.Is(err, ErrCertificate) {
		t.Fatalf("locked issue err = %v", err)
	}
	otherDER, _ := authTestRoot(t)
	foreign, _ := NewAuthority(otherDER, authTestLockedKey)
	if _, err := foreign.verify(der, authTestNow); !errors.Is(err, ErrCertificate) {
		t.Fatal("untrusted cert accepted")
	}
	r := locked.rootDER()
	r[0] ^= 0xff
	if locked.rootDER()[0] == r[0] {
		t.Fatal("rootDER not copied")
	}
}

func TestAuthorityParseCSRStrict(t *testing.T) {
	raw := authTestCSR(t, nil)
	if _, err := parseCSR(append(raw[:len(raw):len(raw)], 0)); !errors.Is(err, ErrCSR) {
		t.Fatal("trailing data accepted")
	}
	bad := append([]byte(nil), raw...)
	bad[len(bad)-1] ^= 1
	if _, err := parseCSR(bad); !errors.Is(err, ErrCSR) {
		t.Fatal("bad signature accepted")
	}
	if _, err := parseCSR(make([]byte, maxCSRBytes+1)); !errors.Is(err, ErrCSR) {
		t.Fatal("oversize accepted")
	}
}

func TestAuthorityRejectsNonCARoot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: authTestNow, NotAfter: authTestNow.Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if _, err := NewAuthority(der, authTestStaticKey(priv)); !errors.Is(err, ErrCertificate) {
		t.Fatal("non-CA root accepted")
	}
}

type authTestSource struct{ pkcs8 []byte }

func (s authTestSource) Open(context.Context, secret.IntegrationID, secret.Scope) (*secret.Value, error) {
	return secret.FromBytes(append([]byte(nil), s.pkcs8...))
}

func TestAuthorityVaultSigningKey(t *testing.T) {
	rootDER, priv := authTestRoot(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(pkcs8))
	for _, bad := range [][]byte{pkcs8, append(append([]byte(nil), encoded...), '\n')} {
		hb, err := secret.NewHandle(authTestSource{bad}, "hub-pki", "ca")
		if err != nil {
			t.Fatal(err)
		}
		ab, _ := NewAuthority(rootDER, VaultSigningKey(hb, "ca"))
		csr, _ := parseCSR(authTestCSR(t, nil))
		if _, err := ab.issue(context.Background(), authTestID(5), csr, authTestNow); !errors.Is(err, ErrCertificate) {
			t.Fatal("non-canonical key encoding accepted")
		}
	}
	h, err := secret.NewHandle(authTestSource{encoded}, "hub-pki", "ca")
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAuthority(rootDER, VaultSigningKey(h, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := parseCSR(authTestCSR(t, nil))
	der, err := a.issue(context.Background(), authTestID(4), csr, authTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.verify(der, authTestNow); err != nil {
		t.Fatal(err)
	}
}
