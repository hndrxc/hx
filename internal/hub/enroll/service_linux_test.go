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
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hndrxc/hx/internal/hub/audit"
)

var fixedNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

// recordingLog appends to a real audit.Log and can be switched to fail.
type recordingLog struct {
	mu     sync.Mutex
	log    *audit.Log
	fail   atomic.Bool
	events []audit.Event
}

func (r *recordingLog) Append(e audit.Event) (audit.Checkpoint, error) {
	if r.fail.Load() {
		return audit.Checkpoint{}, errors.New("injected audit failure")
	}
	cp, err := r.log.Append(e)
	if err == nil {
		r.mu.Lock()
		r.events = append(r.events, e)
		r.mu.Unlock()
	}
	return cp, err
}

func (r *recordingLog) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

type fixture struct {
	t         *testing.T
	dir       string
	auditPath string
	rec       *recordingLog
	authority *Authority
	signs     atomic.Int64
	locked    atomic.Bool
	clock     atomic.Int64
	svc       *Service
	operator  LocalPeer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{t: t, dir: filepath.Join(root, "registry"), auditPath: filepath.Join(root, "audit.log")}
	if err := os.Mkdir(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := audit.Open(f.auditPath, audit.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f.rec = &recordingLog{log: l}
	f.clock.Store(fixedNow.UnixNano())

	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hx test enrollment CA"},
		NotBefore:             fixedNow.Add(-time.Hour),
		NotAfter:              fixedNow.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	f.authority, err = NewAuthority(caDER, func(ctx context.Context, use func(crypto.Signer) error) error {
		f.signs.Add(1)
		if f.locked.Load() {
			return errors.New("vault locked")
		}
		return use(caKey)
	})
	if err != nil {
		t.Fatal(err)
	}
	var opID audit.ID
	opID[0] = 0x0a
	f.operator = LocalPeer{ID: opID, Operator: true}
	f.open()
	return f
}

func (f *fixture) now() time.Time { return time.Unix(0, f.clock.Load()).UTC() }

func (f *fixture) advance(d time.Duration) { f.clock.Add(int64(d)) }

func (f *fixture) open() {
	f.t.Helper()
	s, err := Open(f.dir, f.authority, audit.NewHooks(f.rec))
	if err != nil {
		f.t.Fatal(err)
	}
	s.now = f.now
	f.svc = s
	f.t.Cleanup(func() {
		if err := s.Close(); err != nil {
			f.t.Errorf("close: %v", err)
		}
	})
}

func (f *fixture) reopen() {
	f.t.Helper()
	if err := f.svc.Close(); err != nil {
		f.t.Fatalf("close: %v", err)
	}
	if err := f.svc.Close(); err != nil {
		f.t.Fatalf("second close: %v", err)
	}
	f.open()
}

func newCSR(t *testing.T) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func binding(n string, role Role) Binding {
	tag := "tag:hx-client"
	if role == RoleIngest {
		tag = "tag:hx-agent"
	}
	return Binding{NodeID: "node-" + n, UserID: "user-" + n, Tag: tag}
}

func peerFor(b Binding) TailnetPeer {
	return TailnetPeer{NodeID: b.NodeID, UserID: b.UserID, Tags: []string{"tag:other", b.Tag}}
}

func (f *fixture) enroll(n string, role Role) (Credential, TailnetPeer) {
	f.t.Helper()
	b := binding(n, role)
	csr := newCSR(f.t)
	tok, err := f.svc.Approve(context.Background(), f.operator, b, role, csr)
	if err != nil {
		f.t.Fatalf("approve: %v", err)
	}
	cred, err := f.svc.Enroll(context.Background(), peerFor(b), tok, csr)
	if err != nil {
		f.t.Fatalf("enroll: %v", err)
	}
	if cred.ID.IsZero() || len(cred.CertificateDER) == 0 || len(cred.RootDER) == 0 {
		f.t.Fatal("incomplete credential")
	}
	return cred, peerFor(b)
}

func wantErr(t *testing.T, err error, sentinels ...error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return
		}
	}
	t.Fatalf("error %v is not one of %v", err, sentinels)
}

func TestUnauthorizedOperatorDenied(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	notOp := LocalPeer{ID: f.operator.ID, Operator: false}
	_, err := f.svc.Approve(ctx, notOp, binding("a", RoleRead), RoleRead, newCSR(t))
	wantErr(t, err, ErrDenied)
	wantErr(t, f.svc.AuthorizeLocal(ctx, notOp, ActionAdmin), ErrDenied)
	if err := f.svc.AuthorizeLocal(ctx, f.operator, ActionAdmin); err != nil {
		t.Fatalf("operator admin: %v", err)
	}
	cred, peer := f.enroll("a", RoleIngest)
	wantErr(t, f.svc.Revoke(ctx, notOp, cred.ID), ErrDenied)
	if _, err := f.svc.AuthorizeRemote(ctx, peer, cred.CertificateDER, ActionIngest, cred.ID); err != nil {
		t.Fatalf("non-operator revoke took effect: %v", err)
	}
}

func TestRemoteAdminDenied(t *testing.T) {
	f := newFixture(t)
	for _, role := range []Role{RoleRead, RoleIngest} {
		cred, peer := f.enroll(map[Role]string{RoleRead: "r", RoleIngest: "i"}[role], role)
		_, err := f.svc.AuthorizeRemote(context.Background(), peer, cred.CertificateDER, ActionAdmin, cred.ID)
		wantErr(t, err, ErrDenied)
	}
}

func TestEnrollRejectsWrongCSRAndWhoIs(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := binding("a", RoleRead)
	cases := map[string]struct {
		peer  TailnetPeer
		other bool
	}{
		"wrong csr":   {peer: peerFor(b), other: true},
		"wrong node":  {peer: TailnetPeer{NodeID: "node-x", UserID: b.UserID, Tags: []string{b.Tag}}},
		"wrong user":  {peer: TailnetPeer{NodeID: b.NodeID, UserID: "user-x", Tags: []string{b.Tag}}},
		"missing tag": {peer: TailnetPeer{NodeID: b.NodeID, UserID: b.UserID, Tags: []string{"tag:other"}}},
		"no tags":     {peer: TailnetPeer{NodeID: b.NodeID, UserID: b.UserID}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			csr := newCSR(t)
			tok, err := f.svc.Approve(ctx, f.operator, b, RoleRead, csr)
			if err != nil {
				t.Fatal(err)
			}
			use := csr
			if tc.other {
				use = newCSR(t)
			}
			cred, err := f.svc.Enroll(ctx, tc.peer, tok, use)
			wantErr(t, err, ErrDenied, ErrCSR)
			if len(cred.CertificateDER) != 0 || !cred.ID.IsZero() {
				t.Fatal("credential leaked on denial")
			}
		})
	}
	_, err := f.svc.Approve(ctx, f.operator, b, RoleRead, []byte("not a csr"))
	wantErr(t, err, ErrCSR, ErrDenied)
	_, err = f.svc.Approve(ctx, f.operator, b, Role(0), newCSR(t))
	wantErr(t, err, ErrDenied)
}

func TestTokenSingleUseSequentialAndConcurrent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := binding("a", RoleRead)
	csr := newCSR(t)
	tok, err := f.svc.Approve(ctx, f.operator, b, RoleRead, csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Enroll(ctx, peerFor(b), tok, csr); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.Enroll(ctx, peerFor(b), tok, csr)
	wantErr(t, err, ErrDenied)

	b2 := binding("b", RoleIngest)
	csr2 := newCSR(t)
	tok2, err := f.svc.Approve(ctx, f.operator, b2, RoleIngest, csr2)
	if err != nil {
		t.Fatal(err)
	}
	const n = 32
	var ok atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := f.svc.Enroll(ctx, peerFor(b2), tok2, csr2); err == nil {
				ok.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := ok.Load(); got != 1 {
		t.Fatalf("concurrent replay: %d successes, want 1", got)
	}
}

func TestTokenExpiryAndRestartLoss(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := binding("a", RoleRead)
	csr := newCSR(t)
	tok, err := f.svc.Approve(ctx, f.operator, b, RoleRead, csr)
	if err != nil {
		t.Fatal(err)
	}
	f.advance(5*time.Minute - time.Nanosecond)
	if _, err := f.svc.Enroll(ctx, peerFor(b), tok, csr); err != nil {
		t.Fatalf("enroll just before expiry: %v", err)
	}
	_, err = f.svc.Enroll(ctx, peerFor(b), tok, csr)
	wantErr(t, err, ErrDenied)

	b2 := binding("b", RoleIngest)
	csr = newCSR(t)
	tok, err = f.svc.Approve(ctx, f.operator, b2, RoleIngest, csr)
	if err != nil {
		t.Fatal(err)
	}
	f.advance(5 * time.Minute)
	c, err := f.svc.Enroll(ctx, peerFor(b2), tok, csr)
	wantErr(t, err, ErrExpired)
	if len(c.CertificateDER) != 0 {
		t.Fatal("certificate issued at expiry")
	}
	_, err = f.svc.Enroll(ctx, peerFor(b2), tok, csr)
	wantErr(t, err, ErrDenied)

	csr = newCSR(t)
	tok, err = f.svc.Approve(ctx, f.operator, b2, RoleIngest, csr)
	if err != nil {
		t.Fatal(err)
	}
	f.reopen()
	_, err = f.svc.Enroll(ctx, peerFor(b2), tok, csr)
	wantErr(t, err, ErrDenied)
}

func TestRoleAndDeviceIsolation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, rp := f.enroll("r", RoleRead)
	i, ip := f.enroll("i", RoleIngest)
	if r.ID == i.ID {
		t.Fatal("IDs collide")
	}
	if got, err := f.svc.AuthorizeRemote(ctx, rp, r.CertificateDER, ActionRead, ID{}); err != nil || got != r.ID {
		t.Fatalf("read own: %v %v", got, err)
	}
	if got, err := f.svc.AuthorizeRemote(ctx, ip, i.CertificateDER, ActionIngest, i.ID); err != nil || got != i.ID {
		t.Fatalf("ingest own: %v %v", got, err)
	}
	denials := []struct {
		name   string
		peer   TailnetPeer
		cert   []byte
		action Action
		target ID
	}{
		{"read role ingest", rp, r.CertificateDER, ActionIngest, r.ID},
		{"ingest role read", ip, i.CertificateDER, ActionRead, ID{}},
		{"read cross device", rp, r.CertificateDER, ActionRead, i.ID},
		{"ingest cross device", ip, i.CertificateDER, ActionIngest, r.ID},
		{"cert from other peer", ip, r.CertificateDER, ActionRead, ID{}},
		{"garbage cert", rp, []byte("garbage"), ActionRead, ID{}},
	}
	for _, d := range denials {
		t.Run(d.name, func(t *testing.T) {
			_, err := f.svc.AuthorizeRemote(ctx, d.peer, d.cert, d.action, d.target)
			wantErr(t, err, ErrDenied)
		})
	}
}

func TestCertificateExpiry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, peer := f.enroll("a", RoleRead)
	cert, err := x509.ParseCertificate(cred.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Store(cert.NotAfter.Add(-time.Second).UnixNano())
	if _, err := f.svc.AuthorizeRemote(ctx, peer, cred.CertificateDER, ActionRead, ID{}); err != nil {
		t.Fatalf("cert rejected before expiry: %v", err)
	}
	f.clock.Store(cert.NotAfter.Add(time.Second).UnixNano())
	_, err = f.svc.AuthorizeRemote(ctx, peer, cred.CertificateDER, ActionRead, ID{})
	wantErr(t, err, ErrExpired, ErrDenied)
	_, err = f.svc.Renew(ctx, peer, cred.CertificateDER, newCSR(t))
	wantErr(t, err, ErrExpired, ErrDenied)
}

func TestRenewKeepsIDAndRevokesOld(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	old, peer := f.enroll("a", RoleIngest)
	csr := newCSR(t)
	renewed, err := f.svc.Renew(ctx, peer, old.CertificateDER, csr)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ID != old.ID {
		t.Fatal("renewal changed ID")
	}
	oc, _ := x509.ParseCertificate(old.CertificateDER)
	nc, err := x509.ParseCertificate(renewed.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oc.RawSubjectPublicKeyInfo, nc.RawSubjectPublicKeyInfo) {
		t.Fatal("renewal reused key")
	}
	parsed, _ := x509.ParseCertificateRequest(csr)
	if !bytes.Equal(parsed.RawSubjectPublicKeyInfo, nc.RawSubjectPublicKeyInfo) {
		t.Fatal("renewed cert not bound to CSR key")
	}
	_, err = f.svc.AuthorizeRemote(ctx, peer, old.CertificateDER, ActionIngest, old.ID)
	wantErr(t, err, ErrDenied)
	if _, err := f.svc.AuthorizeRemote(ctx, peer, renewed.CertificateDER, ActionIngest, old.ID); err != nil {
		t.Fatalf("renewed cert: %v", err)
	}
	_, err = f.svc.Renew(ctx, peer, old.CertificateDER, newCSR(t))
	wantErr(t, err, ErrDenied)
	other := peerFor(binding("x", RoleIngest))
	_, err = f.svc.Renew(ctx, other, renewed.CertificateDER, newCSR(t))
	wantErr(t, err, ErrDenied)
	f.reopen()
	_, err = f.svc.AuthorizeRemote(ctx, peer, old.CertificateDER, ActionIngest, old.ID)
	wantErr(t, err, ErrDenied)
}

func TestRevokeSurvivesReopen(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, peer := f.enroll("a", RoleRead)
	keep, keepPeer := f.enroll("b", RoleRead)
	if err := f.svc.Revoke(ctx, f.operator, cred.ID); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.AuthorizeRemote(ctx, peer, cred.CertificateDER, ActionRead, ID{})
	wantErr(t, err, ErrDenied)
	f.reopen()
	_, err = f.svc.AuthorizeRemote(ctx, peer, cred.CertificateDER, ActionRead, ID{})
	wantErr(t, err, ErrDenied)
	_, err = f.svc.Renew(ctx, peer, cred.CertificateDER, newCSR(t))
	wantErr(t, err, ErrDenied)
	if _, err := f.svc.AuthorizeRemote(ctx, keepPeer, keep.CertificateDER, ActionRead, ID{}); err != nil {
		t.Fatalf("unrevoked device lost after reopen: %v", err)
	}
	if fi, err := os.Stat(f.dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("registry dir mode changed: %v %v", fi, err)
	}
}

func TestNoGrantOnAuditFailure(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, peer := f.enroll("a", RoleRead)
	b := binding("b", RoleRead)
	csr := newCSR(t)
	tok, err := f.svc.Approve(ctx, f.operator, b, RoleRead, csr)
	if err != nil {
		t.Fatal(err)
	}
	f.rec.fail.Store(true)
	if _, err := f.svc.Approve(ctx, f.operator, binding("c", RoleRead), RoleRead, newCSR(t)); err == nil {
		t.Fatal("approve granted without audit")
	}
	if c, err := f.svc.Enroll(ctx, peerFor(b), tok, csr); err == nil || len(c.CertificateDER) != 0 {
		t.Fatal("enroll granted without audit")
	}
	if _, err := f.svc.AuthorizeRemote(ctx, peer, cred.CertificateDER, ActionRead, ID{}); err == nil {
		t.Fatal("remote authorization granted without audit")
	}
	if err := f.svc.AuthorizeLocal(ctx, f.operator, ActionAdmin); err == nil {
		t.Fatal("local authorization granted without audit")
	}
	if c, err := f.svc.Renew(ctx, peer, cred.CertificateDER, newCSR(t)); err == nil || len(c.CertificateDER) != 0 {
		t.Fatal("renew granted without audit")
	}
	f.rec.fail.Store(false)
	if _, err := f.svc.AuthorizeRemote(ctx, peer, cred.CertificateDER, ActionRead, ID{}); err != nil {
		t.Fatalf("failed renew must not revoke current cert: %v", err)
	}
}

func TestAuthorizationNeverTouchesSigningKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, peer := f.enroll("a", RoleIngest)
	f.locked.Store(true)
	before := f.signs.Load()
	if _, err := f.svc.AuthorizeRemote(ctx, peer, cred.CertificateDER, ActionIngest, cred.ID); err != nil {
		t.Fatalf("locked remote auth: %v", err)
	}
	_, _ = f.svc.AuthorizeRemote(ctx, peer, cred.CertificateDER, ActionRead, cred.ID)
	if err := f.svc.AuthorizeLocal(ctx, f.operator, ActionAdmin); err != nil {
		t.Fatalf("locked local auth: %v", err)
	}
	if err := f.svc.Revoke(ctx, f.operator, cred.ID); err != nil {
		t.Fatalf("locked revoke: %v", err)
	}
	if got := f.signs.Load(); got != before {
		t.Fatalf("signing key looked up %d times during authorization", got-before)
	}
	_, err := f.svc.Renew(ctx, peer, cred.CertificateDER, newCSR(t))
	wantErr(t, err, ErrDenied, ErrUnavailable)
}

func TestLockedSigningKeyFailsClosed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := binding("a", RoleRead)
	csr := newCSR(t)
	tok, err := f.svc.Approve(ctx, f.operator, b, RoleRead, csr)
	if err != nil {
		t.Fatal(err)
	}
	f.locked.Store(true)
	c, err := f.svc.Enroll(ctx, peerFor(b), tok, csr)
	wantErr(t, err, ErrUnavailable, ErrDenied)
	if len(c.CertificateDER) != 0 {
		t.Fatal("certificate issued while locked")
	}
}

func TestAuditTypedAndPayloadFree(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := binding("a", RoleRead)
	csr := newCSR(t)
	tok, err := f.svc.Approve(ctx, f.operator, b, RoleRead, csr)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := f.svc.Enroll(ctx, peerFor(b), tok, csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AuthorizeRemote(ctx, peerFor(b), cred.CertificateDER, ActionRead, ID{}); err != nil {
		t.Fatal(err)
	}
	_, _ = f.svc.AuthorizeRemote(ctx, peerFor(b), cred.CertificateDER, ActionIngest, cred.ID)

	seen := map[audit.Action]map[audit.Outcome]bool{}
	for _, e := range f.rec.snapshot() {
		if seen[e.Action] == nil {
			seen[e.Action] = map[audit.Outcome]bool{}
		}
		seen[e.Action][e.Outcome] = true
		if !e.At.Equal(fixedNow) {
			t.Fatalf("event time %v not from service clock", e.At)
		}
	}
	if !seen[audit.ActionClientEnrollment][audit.OutcomeAllowed] {
		t.Fatal("missing allowed client_enrollment event")
	}
	if !seen[audit.ActionAPIAuth][audit.OutcomeAllowed] || !seen[audit.ActionAPIAuth][audit.OutcomeDenied] {
		t.Fatalf("missing api_auth outcomes: %v", seen)
	}
	raw, err := os.ReadFile(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(cred.CertificateDER)
	for name, secret := range map[string][]byte{
		"node":   []byte(b.NodeID),
		"user":   []byte(b.UserID),
		"tag":    []byte(b.Tag),
		"csr":    []byte(hex.EncodeToString(csr[:16])),
		"cert":   []byte(hex.EncodeToString(cred.CertificateDER[:16])),
		"spki":   []byte(hex.EncodeToString(cert.RawSubjectPublicKeyInfo)),
		"serial": []byte(cert.SerialNumber.Text(16)),
	} {
		if len(secret) > 4 && bytes.Contains(raw, secret) {
			t.Fatalf("audit log contains %s payload", name)
		}
	}
	_ = tok
}
