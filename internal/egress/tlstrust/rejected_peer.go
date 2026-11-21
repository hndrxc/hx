package tlstrust

import (
	"crypto/tls"
	"errors"
	"time"
)

// NoteVerificationFailure audits a pin-mismatch denial when a standard TLS
// handshake failed before VerifyConnection could run (for example x509
// rejecting a changed self-signed leaf). Call it only after a failed handshake
// with the error that handshake returned.
//
// The unverified peer certificate is used for diagnosis only; it never grants
// trust. It returns nil when nothing needs auditing (the failure is not an x509
// verification failure, carries no chain, the policy has no pin, or the peer
// matches a still-active approved pin), in which case the original handshake
// error stands. When the peer differs from every active pin it audits a denied
// PinMismatch and returns ErrPinMismatch (joined with ErrAudit if the audit
// write failed). The TLS error itself is never exposed.
func (b *Binding) NoteVerificationFailure(err error) error {
	if b == nil || b.store == nil {
		return ErrStore
	}
	var cve *tls.CertificateVerificationError
	if !errors.As(err, &cve) || len(cve.UnverifiedCertificates) == 0 || cve.UnverifiedCertificates[0] == nil {
		return nil
	}
	peer := spkiPin(cve.UnverifiedCertificates[0])

	s := b.store
	s.mu.Lock()
	if err := s.usable(); err != nil {
		s.mu.Unlock()
		return err
	}
	if !validateOrigin(b.origin) {
		s.mu.Unlock()
		return ErrInvalid
	}
	rec, lerr := s.load(b.origin)
	now := s.now()
	s.mu.Unlock()
	if lerr != nil {
		return lerr
	}

	cands := []Candidate{rec.active}
	if rec.staged != nil {
		if now.Before(time.Unix(0, rec.deadline)) {
			cands = append(cands, *rec.staged)
		} else {
			cands = []Candidate{*rec.staged}
		}
	}
	pinned := false
	for _, c := range cands {
		tr, perr := newTrustRecord(b.origin, c)
		if perr != nil {
			return perr
		}
		if !tr.hasPin {
			// An unpinned policy accepts any leaf under its anchors, so a
			// verification failure here is not a pin issue.
			return nil
		}
		pinned = true
		if tr.leafPin == peer {
			return nil
		}
	}
	if !pinned {
		return nil
	}
	if aerr := s.emit(AuditEvent{At: now.UTC(), Origin: b.origin, Action: PinMismatch, Allowed: false}); aerr != nil {
		return errors.Join(ErrPinMismatch, aerr)
	}
	return ErrPinMismatch
}
