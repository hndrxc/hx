//go:build linux

package enroll

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/hndrxc/hx/internal/secret"
)

// ErrCSR reports a rejected certificate signing request. The category is fixed;
// no request material is attached.
var ErrCSR = errors.New("enroll: invalid certificate request")

// ErrCertificate reports a rejected, untrusted, or unissuable certificate.
var ErrCertificate = errors.New("enroll: invalid certificate")

const (
	leafTTL           = 24 * time.Hour
	maxCSRBytes       = 4096
	maxCertBytes      = 8192
	identityURNPrefix = "urn:hx:identity:"
	maxKeyB64Bytes    = 256
)

// SigningKey lends the hub CA private key to fn for the duration of the call.
// Implementations must never retain or export the signer after fn returns.
type SigningKey func(ctx context.Context, fn func(crypto.Signer) error) error

// VaultSigningKey returns a SigningKey that reads an encrypted, hub-owned
// Ed25519 PKCS#8 CA key, stored as canonical single-line standard base64
// (strict padding, no whitespace), from the hub PKI vault handle (a vault instance
// separate from collector credentials). The parsed key is zeroed after fn.
func VaultSigningKey(handle *secret.Handle, scope secret.Scope) SigningKey {
	return func(ctx context.Context, fn func(crypto.Signer) error) error {
		if handle == nil || fn == nil {
			return ErrCertificate
		}
		return handle.Use(ctx, scope, func(plaintext []byte) error {
			if len(plaintext) == 0 || len(plaintext) > maxKeyB64Bytes || !canonicalBase64Bytes(plaintext) {
				return ErrCertificate
			}
			scratch := make([]byte, base64.StdEncoding.DecodedLen(len(plaintext)))
			defer clear(scratch)
			n, err := base64.StdEncoding.Strict().Decode(scratch, plaintext)
			if err != nil || base64.StdEncoding.EncodedLen(n) != len(plaintext) {
				return ErrCertificate
			}
			parsed, err := x509.ParsePKCS8PrivateKey(scratch[:n])
			if err != nil {
				return ErrCertificate
			}
			key, ok := parsed.(ed25519.PrivateKey)
			if !ok || len(key) != ed25519.PrivateKeySize {
				return ErrCertificate
			}
			defer clear(key)
			return fn(key)
		})
	}
}

// canonicalBase64Bytes rejects anything outside the standard alphabet; the Go
// decoder otherwise silently skips CR and LF.
func canonicalBase64Bytes(b []byte) bool {
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '=':
		default:
			return false
		}
	}
	return true
}

// Authority is the hub's client-certificate authority. It holds only the
// public root certificate; the private key is borrowed per issuance.
type Authority struct {
	rootRaw []byte
	root    *x509.Certificate
	pool    *x509.CertPool
	key     SigningKey
}

// NewAuthority validates caDER as a self-signed Ed25519 CA root and binds key.
// It does not open the key, so construction succeeds while the vault is locked.
func NewAuthority(caDER []byte, key SigningKey) (*Authority, error) {
	if key == nil || len(caDER) == 0 || len(caDER) > maxCertBytes {
		return nil, ErrCertificate
	}
	raw := bytes.Clone(caDER)
	root, err := x509.ParseCertificate(raw)
	if err != nil || !bytes.Equal(root.Raw, raw) {
		return nil, ErrCertificate
	}
	if root.PublicKeyAlgorithm != x509.Ed25519 || root.SignatureAlgorithm != x509.PureEd25519 {
		return nil, ErrCertificate
	}
	if _, ok := root.PublicKey.(ed25519.PublicKey); !ok {
		return nil, ErrCertificate
	}
	if !root.BasicConstraintsValid || !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrCertificate
	}
	if !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil {
		return nil, ErrCertificate
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &Authority{rootRaw: raw, root: root, pool: pool, key: key}, nil
}

func (a *Authority) rootDER() []byte { return bytes.Clone(a.rootRaw) }

// parseCSR parses a bounded, exact DER Ed25519 CSR and verifies its
// proof-of-possession signature. Only the public key is used downstream.
func parseCSR(raw []byte) (*x509.CertificateRequest, error) {
	if len(raw) == 0 || len(raw) > maxCSRBytes {
		return nil, ErrCSR
	}
	csr, err := x509.ParseCertificateRequest(raw)
	if err != nil || !bytes.Equal(csr.Raw, raw) {
		return nil, ErrCSR
	}
	if csr.PublicKeyAlgorithm != x509.Ed25519 || csr.SignatureAlgorithm != x509.PureEd25519 {
		return nil, ErrCSR
	}
	if pub, ok := csr.PublicKey.(ed25519.PublicKey); !ok || len(pub) != ed25519.PublicKeySize {
		return nil, ErrCSR
	}
	if csr.CheckSignature() != nil {
		return nil, ErrCSR
	}
	return csr, nil
}

func identityURI(id ID) *url.URL {
	return &url.URL{Scheme: "urn", Opaque: "hx:identity:" + id.String()}
}

// issue signs a 24h client-auth leaf for id over the CSR public key only.
func (a *Authority) issue(ctx context.Context, id ID, csr *x509.CertificateRequest, now time.Time) ([]byte, error) {
	if id.IsZero() || csr == nil {
		return nil, ErrCSR
	}
	pub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize || csr.CheckSignature() != nil {
		return nil, ErrCSR
	}
	if now.Before(a.root.NotBefore) || !now.Before(a.root.NotAfter) {
		return nil, ErrCertificate
	}
	notAfter := now.Add(leafTTL)
	if notAfter.After(a.root.NotAfter) {
		notAfter = a.root.NotAfter
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, ErrCertificate
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: id.String()},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{identityURI(id)},
	}
	rootPub := a.root.PublicKey.(ed25519.PublicKey)
	var der []byte
	err = a.key(ctx, func(signer crypto.Signer) error {
		if signer == nil {
			return ErrCertificate
		}
		sp, ok := signer.Public().(ed25519.PublicKey)
		if !ok || !sp.Equal(rootPub) {
			return ErrCertificate
		}
		out, cerr := x509.CreateCertificate(rand.Reader, tmpl, a.root, pub, signer)
		if cerr != nil {
			return ErrCertificate
		}
		der = out
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrCertificate) {
			return nil, ErrCertificate
		}
		return nil, fmt.Errorf("%w: signing key unavailable", ErrCertificate)
	}
	if len(der) == 0 {
		return nil, ErrCertificate
	}
	return der, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// verify checks raw against the dedicated root pool at now and enforces the
// leaf profile. Expired leaves wrap ErrExpired; anything else is ErrCertificate.
func (a *Authority) verify(raw []byte, now time.Time) (*x509.Certificate, error) {
	if len(raw) == 0 || len(raw) > maxCertBytes {
		return nil, ErrCertificate
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil || !bytes.Equal(cert.Raw, raw) {
		return nil, ErrCertificate
	}
	if !bytes.Equal(cert.RawIssuer, a.root.RawSubject) || cert.CheckSignatureFrom(a.root) != nil {
		return nil, ErrCertificate
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("%w: %w", ErrCertificate, ErrExpired)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       a.pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, ErrCertificate
	}
	if !validLeafProfile(cert) {
		return nil, ErrCertificate
	}
	if _, err := certificateID(cert); err != nil {
		return nil, ErrCertificate
	}
	return cert, nil
}

func validLeafProfile(c *x509.Certificate) bool {
	if c.PublicKeyAlgorithm != x509.Ed25519 || c.SignatureAlgorithm != x509.PureEd25519 {
		return false
	}
	if !c.BasicConstraintsValid || c.IsCA || c.KeyUsage != x509.KeyUsageDigitalSignature {
		return false
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(c.UnknownExtKeyUsage) != 0 {
		return false
	}
	if len(c.DNSNames) != 0 || len(c.EmailAddresses) != 0 || len(c.IPAddresses) != 0 || len(c.URIs) != 1 {
		return false
	}
	return c.NotAfter.Sub(c.NotBefore) <= leafTTL
}

// certificateID extracts the signed identity URI from an issued leaf.
func certificateID(cert *x509.Certificate) (ID, error) {
	if cert == nil || len(cert.URIs) != 1 || cert.URIs[0] == nil {
		return ID{}, ErrCertificate
	}
	s := cert.URIs[0].String()
	if !strings.HasPrefix(s, identityURNPrefix) {
		return ID{}, ErrCertificate
	}
	h := s[len(identityURNPrefix):]
	var id ID
	if len(h) != hex.EncodedLen(len(id)) || strings.ToLower(h) != h {
		return ID{}, ErrCertificate
	}
	if _, err := hex.Decode(id[:], []byte(h)); err != nil || id.IsZero() {
		return ID{}, ErrCertificate
	}
	if cert.URIs[0].String() != identityURI(id).String() {
		return ID{}, ErrCertificate
	}
	return id, nil
}
