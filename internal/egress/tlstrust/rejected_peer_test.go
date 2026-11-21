//go:build linux

package tlstrust

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
)

func TestRejectedPeerPinMismatchAudited(t *testing.T) {
	host := tlsMaterialOrigin.Host
	approved := tlsMaterialSelfSigned(t, host)
	changed := tlsMaterialSelfSigned(t, host)

	var events []AuditEvent
	s, err := Open(t.TempDir(), func(e AuditEvent) error { events = append(events, e); return nil })
	if err != nil {
		t.Skipf("store unavailable: %v", err)
	}
	defer s.Close()
	s.now = tlsMaterialClock(tlsMaterialEpoch)

	cand := Candidate{Mode: PinnedLeaf, Certificates: [][]byte{approved.der}}
	if err := s.Approve(tlsMaterialOrigin, cand, []Pin{tlsMaterialPin(t, approved)}); err != nil {
		t.Fatal(err)
	}
	events = nil
	b := s.Bind(tlsMaterialOrigin)
	cfg, err := b.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	herr := tlsMaterialHandshake(t, cfg, changed)
	if herr == nil {
		t.Fatal("changed leaf accepted")
	}
	if err := b.NoteVerificationFailure(herr); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("note: %v", err)
	}
	if len(events) != 1 || events[0].Action != PinMismatch || events[0].Allowed {
		t.Fatalf("events: %+v", events)
	}

	// Same pin as approved: no audit, original failure stands.
	events = nil
	matching := &tls.CertificateVerificationError{UnverifiedCertificates: []*x509.Certificate{approved.cert}, Err: errors.New("unknown authority")}
	if err := b.NoteVerificationFailure(matching); err != nil || len(events) != 0 {
		t.Fatalf("matching pin: %v %v", err, events)
	}
	// Non-verification errors are ignored.
	if err := b.NoteVerificationFailure(errors.New("boom")); err != nil || len(events) != 0 {
		t.Fatalf("other error: %v %v", err, events)
	}
}
