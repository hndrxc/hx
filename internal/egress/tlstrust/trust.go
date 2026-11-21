// Package tlstrust holds operator-approved TLS trust settings for egress
// origins. Verification is never disabled: the standard chain, host/IP SAN and
// validity checks always run, and approved pins are enforced on the same
// verified chain.
package tlstrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/netip"
	"time"
)

// Origin is a canonical TLS destination.
type Origin struct {
	Scheme string
	Host   string
	Port   uint16
}

// Pin is a SHA-256 fingerprint of a certificate's SubjectPublicKeyInfo.
type Pin [32]byte

// Mode selects how a candidate is trusted.
type Mode string

const (
	// PrivateCA trusts the supplied CA certificates as anchors.
	PrivateCA Mode = "private-ca"
	// PinnedLeaf trusts exactly one self-signed server certificate.
	PinnedLeaf Mode = "pinned-leaf"
)

// Candidate is DER trust material. LeafPin is an optional leaf pin for
// PrivateCA (zero means none) and is ignored for PinnedLeaf.
type Candidate struct {
	Mode         Mode
	Certificates [][]byte
	LeafPin      Pin
}

var (
	// ErrInvalid reports invalid origin, candidate, pins or trust material.
	ErrInvalid = errors.New("tlstrust: invalid trust material")
	// ErrPinMismatch reports a handshake or approval pin mismatch.
	ErrPinMismatch = errors.New("tlstrust: pin mismatch")
)

const (
	maxCertificates = 16
	maxDERLen       = 32 << 10
	maxHostLen      = 253
)

// Discover computes the SPKI fingerprints of the supplied certificates, in
// order, without activating anything.
func Discover(candidate Candidate) ([]Pin, error) {
	certs, err := parseCertificates(candidate)
	if err != nil {
		return nil, err
	}
	pins := make([]Pin, len(certs))
	for i, c := range certs {
		pins[i] = spkiPin(c)
	}
	return pins, nil
}

func spkiPin(c *x509.Certificate) Pin {
	return Pin(sha256.Sum256(c.RawSubjectPublicKeyInfo))
}

func validateOrigin(o Origin) bool {
	switch o.Scheme {
	case "https", "wss", "tls":
	default:
		return false
	}
	if o.Port == 0 || o.Host == "" || len(o.Host) > maxHostLen {
		return false
	}
	if a, err := netip.ParseAddr(o.Host); err == nil {
		return a.String() == o.Host && a.Zone() == ""
	}
	return validDNSName(o.Host)
}

func validDNSName(h string) bool {
	labelLen := 0
	for i := range len(h) {
		ch := h[i]
		switch {
		case ch == '.':
			if labelLen == 0 || h[i-1] == '-' {
				return false
			}
			labelLen = 0
			continue
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
		case ch == '-':
			if labelLen == 0 {
				return false
			}
		default:
			return false
		}
		labelLen++
		if labelLen > 63 {
			return false
		}
	}
	return labelLen > 0 && h[len(h)-1] != '-'
}

// parseCertificates parses and structurally checks a candidate without an
// origin or the current time.
func parseCertificates(c Candidate) ([]*x509.Certificate, error) {
	switch c.Mode {
	case PrivateCA:
	case PinnedLeaf:
		if len(c.Certificates) != 1 {
			return nil, ErrInvalid
		}
	default:
		return nil, ErrInvalid
	}
	if len(c.Certificates) == 0 || len(c.Certificates) > maxCertificates {
		return nil, ErrInvalid
	}
	certs := make([]*x509.Certificate, len(c.Certificates))
	for i, der := range c.Certificates {
		if len(der) == 0 || len(der) > maxDERLen {
			return nil, ErrInvalid
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrInvalid
		}
		for _, prev := range certs[:i] {
			if bytes.Equal(prev.Raw, cert.Raw) {
				return nil, ErrInvalid
			}
		}
		certs[i] = cert
	}
	for _, cert := range certs {
		if c.Mode == PrivateCA {
			if !cert.BasicConstraintsValid || !cert.IsCA {
				return nil, ErrInvalid
			}
			if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
				return nil, ErrInvalid
			}
			continue
		}
		if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			return nil, ErrInvalid
		}
		if cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil {
			return nil, ErrInvalid
		}
	}
	return certs, nil
}

// validateMaterial checks origin-bound structural constraints without
// consulting the current time.
func validateMaterial(o Origin, c Candidate) error {
	_, err := parseMaterial(o, c)
	return err
}

func parseMaterial(o Origin, c Candidate) ([]*x509.Certificate, error) {
	if !validateOrigin(o) {
		return nil, ErrInvalid
	}
	certs, err := parseCertificates(c)
	if err != nil {
		return nil, err
	}
	if c.Mode == PinnedLeaf && certs[0].VerifyHostname(o.Host) != nil {
		return nil, ErrInvalid
	}
	return certs, nil
}

// validateCandidate additionally requires current validity of every
// certificate and exact out-of-band pin agreement: one pin per certificate in
// order, plus the leaf pin last when PrivateCA carries one.
func validateCandidate(o Origin, c Candidate, outOfBand []Pin, now time.Time) error {
	certs, err := parseMaterial(o, c)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return ErrInvalid
		}
	}
	want := make([]Pin, 0, len(certs)+1)
	for _, cert := range certs {
		want = append(want, spkiPin(cert))
	}
	if c.Mode == PrivateCA && c.LeafPin != (Pin{}) {
		want = append(want, c.LeafPin)
	}
	if len(outOfBand) != len(want) {
		return ErrInvalid
	}
	var zero Pin
	for _, p := range outOfBand {
		if p == zero {
			return ErrInvalid
		}
	}
	for _, w := range want {
		if w == zero {
			return ErrInvalid
		}
	}
	match := 1
	for i := range want {
		match &= subtle.ConstantTimeCompare(want[i][:], outOfBand[i][:])
	}
	if match != 1 {
		return ErrPinMismatch
	}
	return nil
}

type trustRecord struct {
	roots   []*x509.Certificate
	exact   []byte // pinned-leaf: the only acceptable leaf
	leafPin Pin
	hasPin  bool
}

func newTrustRecord(o Origin, c Candidate) (*trustRecord, error) {
	certs, err := parseMaterial(o, c)
	if err != nil {
		return nil, err
	}
	r := &trustRecord{roots: certs}
	if c.Mode == PinnedLeaf {
		r.exact = certs[0].Raw
		r.leafPin, r.hasPin = spkiPin(certs[0]), true
	} else if c.LeafPin != (Pin{}) {
		r.leafPin, r.hasPin = c.LeafPin, true
	}
	return r, nil
}

// accepts reports whether one verified chain satisfies this record: the
// chain's root is one of the record's exact anchors and the leaf condition
// holds on that same chain.
func (r *trustRecord) accepts(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	root, leaf := chain[len(chain)-1], chain[0]
	found := false
	for _, a := range r.roots {
		if bytes.Equal(a.Raw, root.Raw) {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	if r.exact != nil && !bytes.Equal(r.exact, leaf.Raw) {
		return false
	}
	if r.hasPin {
		p := spkiPin(leaf)
		if subtle.ConstantTimeCompare(p[:], r.leafPin[:]) != 1 {
			return false
		}
	}
	return true
}

// configFor builds a client TLS config for o. With next set, current is
// trusted only while now() < until, after which only next is trusted; the
// cutoff is re-evaluated in the handshake callback. onMismatch, if non-nil,
// runs on a pin mismatch and its error replaces ErrPinMismatch.
func configFor(o Origin, current Candidate, next *Candidate, until time.Time, now func() time.Time, onMismatch func() error) (*tls.Config, error) {
	if now == nil {
		return nil, ErrInvalid
	}
	cur, err := newTrustRecord(o, current)
	if err != nil {
		return nil, err
	}
	var nxt *trustRecord
	if next != nil {
		if until.IsZero() {
			return nil, ErrInvalid
		}
		if nxt, err = newTrustRecord(o, *next); err != nil {
			return nil, err
		}
	}
	active := func(t time.Time) []*trustRecord {
		switch {
		case nxt == nil:
			return []*trustRecord{cur}
		case !t.Before(until):
			return []*trustRecord{nxt}
		default:
			return []*trustRecord{cur, nxt}
		}
	}
	pool := x509.NewCertPool()
	for _, r := range active(now()) {
		for _, c := range r.roots {
			pool.AddCert(c)
		}
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		ServerName:             o.Host,
		RootCAs:                pool,
		Time:                   now,
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil,
		Renegotiation:          tls.RenegotiateNever,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				for _, r := range active(now()) {
					for _, chain := range cs.VerifiedChains {
						if len(chain) > 0 && bytes.Equal(chain[0].Raw, cs.PeerCertificates[0].Raw) && r.accepts(chain) {
							return nil
						}
					}
				}
			}
			if onMismatch != nil {
				if err := onMismatch(); err != nil {
					return err
				}
			}
			return ErrPinMismatch
		},
	}, nil
}
