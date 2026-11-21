package client

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// ErrEnrollment is the fixed-category error for local enrollment failures.
// It never carries key, CSR, certificate, or token material.
var ErrEnrollment = errors.New("client: enrollment failed")

// ErrKeyMismatch reports that an issued certificate does not bind the
// locally generated signer.
var ErrKeyMismatch = errors.New("client: certificate does not match local key")

// NewEnrollmentKey generates a fresh local Ed25519 key and a self-signed
// (proof-of-possession) DER certificate request for it. The private key never
// leaves this process; only the CSR is sent to the hub.
func NewEnrollmentKey() (crypto.Signer, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, ErrEnrollment
	}
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "hx-client"},
		SignatureAlgorithm: x509.PureEd25519,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return nil, nil, ErrEnrollment
	}
	return priv, der, nil
}

// maxCertDER bounds accepted certificate encodings.
const maxCertDER = 16 << 10

// VerifyIssuedLeaf checks, with no ambient roots, that:
//   - hubCADER and leafDER are each exactly one DER certificate within size;
//   - the pinned hub CA (obtained out-of-band before any token was sent) is a
//     self-signed Ed25519 CA with cert-sign usage, valid now;
//   - the leaf is a non-CA, digital-signature-only, ClientAuth-only Ed25519
//     certificate valid now and signed by that CA;
//   - the leaf binds the public key of signer.
//
// Any failure returns a fixed-category error.
func VerifyIssuedLeaf(signer crypto.Signer, leafDER, hubCADER []byte) error {
	return verifyIssuedLeafAt(signer, leafDER, hubCADER, time.Now())
}

func verifyIssuedLeafAt(signer crypto.Signer, leafDER, hubCADER []byte, now time.Time) error {
	if signer == nil || len(leafDER) == 0 || len(hubCADER) == 0 ||
		len(leafDER) > maxCertDER || len(hubCADER) > maxCertDER {
		return ErrEnrollment
	}
	ca, err := x509.ParseCertificate(hubCADER) // rejects trailing data
	if err != nil || !bytes.Equal(ca.Raw, hubCADER) {
		return ErrEnrollment
	}
	if _, ok := ca.PublicKey.(ed25519.PublicKey); !ok ||
		ca.SignatureAlgorithm != x509.PureEd25519 ||
		!ca.IsCA || !ca.BasicConstraintsValid ||
		ca.KeyUsage&x509.KeyUsageCertSign == 0 ||
		!bytes.Equal(ca.RawSubject, ca.RawIssuer) ||
		ca.CheckSignatureFrom(ca) != nil ||
		now.Before(ca.NotBefore) || now.After(ca.NotAfter) {
		return ErrEnrollment
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil || !bytes.Equal(leaf.Raw, leafDER) {
		return ErrEnrollment
	}
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok ||
		leaf.SignatureAlgorithm != x509.PureEd25519 ||
		leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(leaf.UnknownExtKeyUsage) != 0 {
		return ErrEnrollment
	}
	roots := x509.NewCertPool() // only the pinned CA; never system roots
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return ErrEnrollment
	}
	want, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return ErrEnrollment
	}
	if !bytes.Equal(want, leaf.RawSubjectPublicKeyInfo) {
		return ErrKeyMismatch
	}
	return nil
}

// Identity is the single enrolled credential bundle a client holds for one
// hub. It has no provider fields and is never derived from flags, env, or
// plaintext config.
type Identity struct {
	// HubScope names the hub this identity belongs to.
	HubScope string
	// Key is the client's private key, held behind crypto.Signer so
	// platform stores may keep it non-exportable.
	Key crypto.Signer
	// LeafDER is the hub-issued client certificate.
	LeafDER []byte
	// HubCADER is the pinned hub root certificate.
	HubCADER []byte
}

const redactedIdentity = "client.Identity{REDACTED}"

// String redacts the bundle; Identity never formats key or cert material.
func (Identity) String() string { return redactedIdentity }

// GoString redacts the bundle for %#v.
func (Identity) GoString() string { return redactedIdentity }

// Format redacts the bundle for every fmt verb, including %+v and %#v.
func (Identity) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedIdentity) }

// MarshalJSON emits a fixed redacted value so encoding/json never serializes
// the private key or certificates. Storage adapters persist an Identity only
// through the protected EnrollmentStore contract, never via JSON.
func (Identity) MarshalJSON() ([]byte, error) {
	return []byte(`"client.Identity{REDACTED}"`), nil
}

// LogValue redacts the bundle for log/slog.
func (Identity) LogValue() slog.Value { return slog.StringValue(redactedIdentity) }

// EnrollmentStore persists exactly one Identity per hub scope.
//
// Contract for every implementation:
//   - Save replaces the bundle atomically: readers observe either the old or
//     the new bundle, never a mix. On Linux this means a private 0700
//     directory owned by the user, regular 0600 files owned by the user, no
//     symlinks, link count 1, write-to-temp + fsync + rename + directory
//     fsync.
//   - Load validates before returning: permissions/ownership as above, the
//     leaf parses, chains to HubCADER, and matches Key (VerifyIssuedLeaf).
//     Any violation fails closed with a fixed-category error.
//   - Delete removes the bundle and syncs the directory.
//   - Windows: per-user, service-SID-bound Credential Manager/DPAPI user
//     scope only; machine scope is forbidden.
//   - macOS: Keychain item scoped by app, service, and access group; runtime
//     is unsupported per ADR-0005.
//   - Windows and macOS require the platform secure store; there is no
//     plaintext fallback. The only raw-key exception is Linux, where the key
//     may be stored as raw PKCS#8 DER solely inside the designated protected
//     store described above, never in config or ambient files.
//   - Key material crosses the adapter only as PKCS#8 DER (for example to
//     import into DPAPI) held in a short-lived buffer that the adapter zeroes
//     after use; it is never logged or formatted.
//
// This package defines the contract only; no backend ships here.
type EnrollmentStore interface {
	Load(hubScope string) (Identity, error)
	Save(id Identity) error
	Delete(hubScope string) error
}
