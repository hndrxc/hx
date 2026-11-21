package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestNewEnrollmentKeyCSRProof(t *testing.T) {
	signer, der, err := NewEnrollmentKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if !signer.Public().(ed25519.PublicKey).Equal(csr.PublicKey) {
		t.Fatal("csr key differs from signer")
	}
}

func testCA(t *testing.T) (*x509.Certificate, []byte, ed25519.PrivateKey) {
	t.Helper()
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	return ca, caDER, caKey
}

func leafTemplate(nb, na time.Time) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: nb, NotAfter: na,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
}

func TestVerifyIssuedLeaf(t *testing.T) {
	ca, caDER, caKey := testCA(t)
	signer, _, err := NewEnrollmentKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := NewEnrollmentKey()
	now := time.Now()
	valid := leafTemplate(now.Add(-time.Hour), now.Add(time.Hour))
	mk := func(tmpl *x509.Certificate, pub any) []byte {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	good := mk(valid, signer.Public())
	if err := VerifyIssuedLeaf(signer, good, caDER); err != nil {
		t.Fatal(err)
	}
	if err := VerifyIssuedLeaf(signer, mk(valid, other.Public()), caDER); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("wrong key: got %v", err)
	}
	expired := mk(leafTemplate(now.Add(-2*time.Hour), now.Add(-time.Hour)), signer.Public())
	serverAuth := leafTemplate(now.Add(-time.Hour), now.Add(time.Hour))
	serverAuth.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	extraUsage := leafTemplate(now.Add(-time.Hour), now.Add(time.Hour))
	extraUsage.KeyUsage |= x509.KeyUsageKeyEncipherment
	_, otherCADER, _ := testCA(t)
	for name, c := range map[string]struct{ leaf, ca []byte }{
		"expired":    {expired, caDER},
		"serverAuth": {mk(serverAuth, signer.Public()), caDER},
		"extraUsage": {mk(extraUsage, signer.Public()), caDER},
		"otherCA":    {good, otherCADER},
		"trailing":   {append(append([]byte{}, good...), 0), caDER},
		"caTrailing": {good, append(append([]byte{}, caDER...), 0)},
		"leafAsCA":   {good, good},
		"empty":      {nil, caDER},
	} {
		if err := VerifyIssuedLeaf(signer, c.leaf, c.ca); !errors.Is(err, ErrEnrollment) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestIdentityRedacted(t *testing.T) {
	signer, _, _ := NewEnrollmentKey()
	id := Identity{HubScope: "hub", Key: signer, LeafDER: []byte{1, 2, 3}}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "id", id)
	for _, out := range []string{fmt.Sprint(id), fmt.Sprintf("%+v", id), fmt.Sprintf("%#v", id),
		fmt.Sprintf("%v", &id), fmt.Sprintf("%x", id), buf.String()} {
		if !strings.Contains(out, "REDACTED") || strings.Contains(out, "LeafDER") || strings.Contains(out, "Key") {
			t.Errorf("unredacted: %q", out)
		}
	}
}

func TestIdentityJSONRedacted(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	id := Identity{HubScope: "hub", Key: priv, LeafDER: []byte{1, 2, 3}}
	nested := struct{ ID Identity }{id}
	for name, v := range map[string]any{"value": id, "pointer": &id, "nested": nested} {
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "REDACTED") ||
			strings.Contains(string(out), base64.StdEncoding.EncodeToString(priv)) ||
			strings.Contains(string(out), base64.StdEncoding.EncodeToString(priv.Seed())) ||
			strings.Contains(string(out), "Key") {
			t.Errorf("%s: unredacted JSON %s", name, out)
		}
	}
}
