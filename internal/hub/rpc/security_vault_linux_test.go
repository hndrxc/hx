//go:build linux && securityfoundation

package rpc

// S09 security-foundation fixture: vault lifecycle, scoped unseal and audit
// fail-closed behaviour exercised through the production vault, secret and
// audit packages. Everything here is TEST-ONLY. The only fake is the
// deliberately marked synthetic terminal (a kernel pseudo-terminal pair
// driven by the test), which feeds secret.TerminalPrompter through its real
// echo-disabled read path; no production bypass exists or is added.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hndrxc/hx/internal/hub/audit"
	"github.com/hndrxc/hx/internal/hub/vault"
	"github.com/hndrxc/hx/internal/secret"
)

const (
	// fixtureIntegrationA owns the credential handed to the caller.
	fixtureIntegrationA secret.IntegrationID = "fixture-a"
	// fixtureIntegrationB is a real alternate record that must never be
	// reachable through A's handle, and vice versa.
	fixtureIntegrationB secret.IntegrationID = "fixture-b"
	fixtureScope        secret.Scope         = "token"
	fixtureAbsentScope  secret.Scope         = "webhook"

	// promptBound hard-bounds every synthetic terminal exchange.
	promptBound = 10 * time.Second
	// scenarioBound hard-bounds a whole helper or subtest.
	scenarioBound = 60 * time.Second
)

// fixtureOperator is a synthetic operator identity.
var fixtureOperator = audit.ID{0x5e, 0xc0, 0x09}

// syntheticTerminal is a TEST-ONLY SYNTHETIC FAKE terminal: a pty pair whose
// slave end is handed to the production secret.TerminalPrompter. Echo is
// disabled before any input is queued, so passphrases never travel back
// through the master side, and the prompter's own output goes to a private
// buffer that is scanned for leaks.
type syntheticTerminal struct {
	master *os.File
	slave  *os.File
	out    bytes.Buffer
	once   sync.Once
}

func newSyntheticTerminal(t *testing.T) *syntheticTerminal {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("synthetic terminal: pty multiplexer unavailable")
	}
	mfd := int(m.Fd())
	if err := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		_ = m.Close()
		t.Fatal("synthetic terminal: unlock pty failed")
	}
	n, err := unix.IoctlGetUint32(mfd, unix.TIOCGPTN)
	if err != nil {
		_ = m.Close()
		t.Fatal("synthetic terminal: pty number unavailable")
	}
	s, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = m.Close()
		t.Fatal("synthetic terminal: open pty slave failed")
	}
	st := &syntheticTerminal{master: m, slave: s}
	t.Cleanup(st.close)
	tio, err := unix.IoctlGetTermios(int(s.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal("synthetic terminal: read termios failed")
	}
	tio.Lflag &^= unix.ECHO | unix.ECHONL
	if err := unix.IoctlSetTermios(int(s.Fd()), unix.TCSETS, tio); err != nil {
		t.Fatal("synthetic terminal: disable echo failed")
	}
	return st
}

func (st *syntheticTerminal) close() {
	st.once.Do(func() {
		_ = st.master.Close()
		_ = st.slave.Close()
	})
}

func (st *syntheticTerminal) prompter() secret.TerminalPrompter {
	return secret.TerminalPrompter{In: st.slave, Out: &st.out}
}

// run queues lines on the terminal and runs op within promptBound. On
// timeout the pty is torn down so the blocked read returns.
func (st *syntheticTerminal) run(t *testing.T, lines []string, op func(secret.TerminalPrompter) error) error {
	t.Helper()
	var in []byte
	for _, l := range lines {
		in = append(in, l...)
		in = append(in, '\n')
	}
	_, err := st.master.Write(in)
	clear(in)
	if err != nil {
		t.Fatal("synthetic terminal: queue input failed")
	}
	p := st.prompter()
	done := make(chan error, 1)
	go func() { done <- op(p) }()
	timer := time.NewTimer(promptBound)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		st.close()
		<-done
		t.Fatal("synthetic terminal: prompt exceeded bound")
		return nil
	}
}

// securityVault is the fixture state behind newSecurityVault.
type securityVault struct {
	dir   string
	hooks audit.Hooks
	term  *syntheticTerminal
	pass  string
	v     *vault.Vault
	a     *secret.Handle
	b     *secret.Handle
	bVal  string
}

func randomFixture(t *testing.T, prefix string) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal("fixture: random source unavailable")
	}
	return prefix + hex.EncodeToString(b[:])
}

func fixtureValue(t *testing.T, s string) *secret.Value {
	t.Helper()
	b := []byte(s)
	v, err := secret.FromBytes(b)
	clear(b)
	if err != nil {
		t.Fatal("fixture: secret value rejected")
	}
	return v
}

func (sv *securityVault) open(t *testing.T) {
	t.Helper()
	v, err := vault.Open(sv.dir, sv.hooks)
	if err != nil {
		t.Fatal("vault: open failed")
	}
	sv.v = v
}

func (sv *securityVault) restart(t *testing.T) {
	t.Helper()
	if err := sv.v.Close(); err != nil {
		t.Fatal("vault: close failed")
	}
	sv.open(t)
}

func (sv *securityVault) unlock(t *testing.T, pass string) error {
	t.Helper()
	return sv.term.run(t, []string{pass}, func(p secret.TerminalPrompter) error {
		return sv.v.PromptUnlock(context.Background(), fixtureOperator, p)
	})
}

func (sv *securityVault) put(t *testing.T, in secret.IntegrationID, sc secret.Scope, s string) error {
	t.Helper()
	x := fixtureValue(t, s)
	defer x.Destroy()
	return sv.v.Put(context.Background(), fixtureOperator, in, sc, x)
}

// withCredential releases A's fixture credential through its scoped handle.
func (sv *securityVault) withCredential(ctx context.Context, fn func([]byte) error) error {
	return sv.a.Use(ctx, fixtureScope, fn)
}

// newSecurityVault builds a production vault in a private temp dir,
// initializes it through PromptInitialize on the synthetic terminal, stores
// fixtureCredential for integration A and a distinct record for integration
// B, proves locked and restarted access is denied, unlocks through
// PromptUnlock, proves cross-integration and undeclared-scope denials, and
// returns a release function bound to A's scoped handle. The vault is
// locked and closed at test cleanup.
func newSecurityVault(t *testing.T, hooks audit.Hooks, fixtureCredential string) (withCredential func(context.Context, func([]byte) error) error) {
	t.Helper()
	return openSecurityVault(t, hooks, fixtureCredential).withCredential
}

func openSecurityVault(t *testing.T, hooks audit.Hooks, fixtureCredential string) *securityVault {
	t.Helper()
	if fixtureCredential == "" {
		t.Fatal("fixture: empty credential")
	}
	ctx, cancel := context.WithTimeout(context.Background(), scenarioBound)
	defer cancel()

	dir := filepath.Join(t.TempDir(), "vault")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal("fixture: create vault dir failed")
	}
	sv := &securityVault{
		dir:   dir,
		hooks: hooks,
		term:  newSyntheticTerminal(t),
		pass:  randomFixture(t, "fixture-pass-"),
		bVal:  randomFixture(t, "fixture-b-"),
	}
	sv.open(t)
	t.Cleanup(func() {
		_ = sv.v.Lock(context.Background(), fixtureOperator)
		_ = sv.v.Close()
	})

	if !sv.v.Locked() {
		t.Fatal("vault: fresh open is not locked")
	}
	if err := sv.term.run(t, []string{sv.pass, sv.pass}, func(p secret.TerminalPrompter) error {
		return sv.v.PromptInitialize(ctx, fixtureOperator, p)
	}); err != nil {
		t.Fatal("vault: PromptInitialize failed")
	}
	if err := sv.put(t, fixtureIntegrationA, fixtureScope, fixtureCredential); err != nil {
		t.Fatal("vault: put A failed")
	}
	if err := sv.put(t, fixtureIntegrationB, fixtureScope, sv.bVal); err != nil {
		t.Fatal("vault: put B failed")
	}

	// Locked, then restarted: access denied before unlock.
	if err := sv.v.Lock(ctx, fixtureOperator); err != nil {
		t.Fatal("vault: lock failed")
	}
	mustDenyLocked(t, sv.v, "after lock")
	sv.restart(t)
	mustDenyLocked(t, sv.v, "after restart")

	wrong := randomFixture(t, "fixture-wrong-")
	if err := sv.unlock(t, wrong); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatal("vault: wrong passphrase not rejected as authentication failure")
	}
	mustDenyLocked(t, sv.v, "after wrong passphrase")
	if err := sv.unlock(t, sv.pass); err != nil {
		t.Fatal("vault: PromptUnlock failed")
	}

	var err error
	if sv.a, err = secret.NewHandle(sv.v, fixtureIntegrationA, fixtureScope); err != nil {
		t.Fatal("secret: handle A rejected")
	}
	if sv.b, err = secret.NewHandle(sv.v, fixtureIntegrationB, fixtureScope, fixtureAbsentScope); err != nil {
		t.Fatal("secret: handle B rejected")
	}

	// A's handle cannot reach an undeclared scope (no Source.Open).
	called := false
	if err := sv.a.Use(ctx, fixtureAbsentScope, func([]byte) error { called = true; return nil }); !errors.Is(err, secret.ErrScopeNotDeclared) || called {
		t.Fatal("secret: undeclared scope on A was not denied")
	}
	// B's handle yields only B's record, never A's value.
	if err := sv.b.Use(ctx, fixtureScope, func(p []byte) error {
		if subtle.ConstantTimeCompare(p, []byte(sv.bVal)) != 1 {
			return errors.New("fixture: B handle released a foreign value")
		}
		return nil
	}); err != nil {
		t.Fatal("secret: B handle did not release exactly B's record")
	}
	// B's declared but absent scope is denied by the vault, not
	// satisfied from A.
	called = false
	if err := sv.b.Use(ctx, fixtureAbsentScope, func([]byte) error { called = true; return nil }); !errors.Is(err, secret.ErrNotFound) || called {
		t.Fatal("secret: absent B scope was not denied")
	}
	return sv
}

func mustDenyLocked(t *testing.T, v *vault.Vault, when string) {
	t.Helper()
	if !v.Locked() {
		t.Fatal("vault: not locked " + when)
	}
	x, err := v.Open(context.Background(), fixtureIntegrationA, fixtureScope)
	if x != nil {
		x.Destroy()
	}
	if !errors.Is(err, secret.ErrLocked) {
		t.Fatal("vault: access not denied as locked " + when)
	}
}

// auditRecorder wraps a real audit.Log, recording successful appends and
// optionally injecting an unavailable sink.
type auditRecorder struct {
	mu     sync.Mutex
	path   string
	log    *audit.Log
	fail   bool
	head   audit.Checkpoint
	events []audit.Event
}

var errSinkUnavailable = errors.New("fixture: audit sink unavailable")

func newAuditRecorder(t *testing.T) *auditRecorder {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal("audit: create dir failed")
	}
	r := &auditRecorder{path: filepath.Join(dir, "audit.jsonl"), head: audit.Genesis()}
	l, err := audit.Open(r.path, audit.OpenOptions{})
	if err != nil {
		t.Fatal("audit: open failed")
	}
	r.log = l
	t.Cleanup(func() { _ = l.Close() })
	return r
}

func (r *auditRecorder) Append(e audit.Event) (audit.Checkpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return audit.Checkpoint{}, errSinkUnavailable
	}
	cp, err := r.log.Append(e)
	if err == nil {
		r.head = cp
		r.events = append(r.events, e)
	}
	return cp, err
}

func (r *auditRecorder) setFail(f bool) {
	r.mu.Lock()
	r.fail = f
	r.mu.Unlock()
}

func (r *auditRecorder) snapshot() (audit.Checkpoint, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.head, len(r.events)
}

func (r *auditRecorder) since(n int) []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events[n:]...)
}

// verifyAnchored proves the on-disk chain contains anchor and ends exactly
// at the recorder's last acknowledged head.
func (r *auditRecorder) verifyAnchored(t *testing.T, anchor audit.Checkpoint) {
	t.Helper()
	f, err := os.Open(r.path)
	if err != nil {
		t.Fatal("audit: reopen for verification failed")
	}
	defer f.Close()
	head, err := audit.Verify(f, &anchor)
	if err != nil {
		t.Fatal("audit: anchored verification failed")
	}
	want, _ := r.snapshot()
	if head != want {
		t.Fatal("audit: on-disk head differs from acknowledged head")
	}
}

// fixtureAuditID mirrors the vault's pseudonymous integration audit ID.
func fixtureAuditID(i secret.IntegrationID) audit.ID {
	h := sha256.Sum256(append([]byte("hx vault integration v1\x00"), string(i)...))
	var id audit.ID
	copy(id[:], h[:])
	return id
}

type decision struct {
	action  audit.Action
	outcome audit.Outcome
	integ   audit.ID
}

func mustDecisions(t *testing.T, got []audit.Event, want []decision) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("audit: got %d decisions, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.Action != w.action || g.Outcome != w.outcome || g.IntegrationID != w.integ {
			t.Fatalf("audit: decision %d = %s/%s, want %s/%s", i, g.Action, g.Outcome, w.action, w.outcome)
		}
	}
}

// assertNoLeak scans captured output and every regular file under dirs for
// the plaintext, hex and base64 forms of each sensitive string.
func assertNoLeak(t *testing.T, captured []byte, sensitive []string, dirs ...string) {
	t.Helper()
	var needles [][]byte
	for _, s := range sensitive {
		needles = append(needles, []byte(s), []byte(hex.EncodeToString([]byte(s))), []byte(base64.StdEncoding.EncodeToString([]byte(s))))
	}
	check := func(b []byte, what string) {
		for _, n := range needles {
			if bytes.Contains(b, n) {
				t.Fatal("leak: sensitive fixture material found in " + what)
			}
		}
	}
	check(captured, "captured output")
	for _, d := range dirs {
		err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || !e.Type().IsRegular() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			check(b, "persisted file "+e.Name())
			return nil
		})
		if err != nil {
			t.Fatal("leak: scan failed")
		}
	}
}

func TestSecurityVaultScopedRelease(t *testing.T) {
	rec := newAuditRecorder(t)
	cred := randomFixture(t, "fixture-cred-")
	withCredential := newSecurityVault(t, audit.NewHooks(rec), cred)
	ctx, cancel := context.WithTimeout(context.Background(), scenarioBound)
	defer cancel()
	anchor, n := rec.snapshot()
	if err := withCredential(ctx, func(p []byte) error {
		if subtle.ConstantTimeCompare(p, []byte(cred)) != 1 {
			return errors.New("fixture: wrong credential released")
		}
		return nil
	}); err != nil {
		t.Fatal("release: scoped credential not released")
	}
	mustDecisions(t, rec.since(n), []decision{{audit.ActionSecretAccess, audit.OutcomeAllowed, fixtureAuditID(fixtureIntegrationA)}})
	rec.verifyAnchored(t, anchor)
	assertNoLeak(t, nil, []string{cred}, filepath.Dir(rec.path))
}

func TestSecurityFoundationFailClosed(t *testing.T) {
	idA := fixtureAuditID(fixtureIntegrationA)
	idB := fixtureAuditID(fixtureIntegrationB)
	mustNotRelease := func(t *testing.T, sv *securityVault, want error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), scenarioBound)
		defer cancel()
		called := false
		err := sv.withCredential(ctx, func([]byte) error { called = true; return nil })
		if called {
			t.Fatal("release: credential released on fail-closed path")
		}
		if !errors.Is(err, want) {
			t.Fatal("release: unexpected denial class")
		}
	}
	leakCheck := func(t *testing.T, sv *securityVault, rec *auditRecorder, cred string) {
		t.Helper()
		assertNoLeak(t, sv.term.out.Bytes(), []string{cred, sv.bVal, sv.pass}, sv.dir, filepath.Dir(rec.path))
	}

	t.Run("unconfigured audit refuses initialize", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "vault")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal("fixture: create vault dir failed")
		}
		v, err := vault.Open(dir, audit.NewHooks(nil))
		if err != nil {
			t.Fatal("vault: open failed")
		}
		defer v.Close()
		term := newSyntheticTerminal(t)
		pass := randomFixture(t, "fixture-pass-")
		err = term.run(t, []string{pass, pass}, func(p secret.TerminalPrompter) error {
			return v.PromptInitialize(context.Background(), fixtureOperator, p)
		})
		if !errors.Is(err, audit.ErrHooksUnconfigured) {
			t.Fatal("vault: initialize without audit sink not refused")
		}
		mustDenyLocked(t, v, "after refused initialize")
		if _, err := os.Lstat(filepath.Join(dir, "vault.sealed")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("vault: refused initialize persisted an image")
		}
		assertNoLeak(t, term.out.Bytes(), []string{pass}, dir)
	})

	t.Run("audit sink failure denies release and lock still erases key", func(t *testing.T) {
		rec := newAuditRecorder(t)
		cred := randomFixture(t, "fixture-cred-")
		sv := openSecurityVault(t, audit.NewHooks(rec), cred)
		anchor, n := rec.snapshot()

		rec.setFail(true)
		mustNotRelease(t, sv, errSinkUnavailable)
		if err := sv.v.Lock(context.Background(), fixtureOperator); !errors.Is(err, errSinkUnavailable) {
			t.Fatal("vault: lock did not surface audit failure")
		}
		if !sv.v.Locked() {
			t.Fatal("vault: key retained after lock with failed audit")
		}
		rec.setFail(false)
		mustDenyLocked(t, sv.v, "after audit-failed lock")

		// Closed sink: unlock is refused and nothing is released.
		if err := rec.log.Close(); err != nil {
			t.Fatal("audit: close failed")
		}
		if err := sv.unlock(t, sv.pass); !errors.Is(err, audit.ErrLogClosed) {
			t.Fatal("vault: unlock with closed audit sink not refused")
		}
		mustDenyLocked(t, sv.v, "after closed-sink unlock")
		mustNotRelease(t, sv, secret.ErrLocked)

		// Only the denial made while the sink was healthy is acknowledged;
		// nothing was granted and nothing was recorded while it was down.
		mustDecisions(t, rec.since(n), []decision{{audit.ActionSecretAccess, audit.OutcomeDenied, idA}})
		rec.verifyAnchored(t, anchor)
		leakCheck(t, sv, rec, cred)
	})

	t.Run("storage failure locks and is audited", func(t *testing.T) {
		rec := newAuditRecorder(t)
		cred := randomFixture(t, "fixture-cred-")
		sv := openSecurityVault(t, audit.NewHooks(rec), cred)
		anchor, n := rec.snapshot()

		// Replace the sealed image with a directory inside the test dir.
		sealed := filepath.Join(sv.dir, "vault.sealed")
		if err := os.Rename(sealed, filepath.Join(t.TempDir(), "sealed.bak")); err != nil {
			t.Fatal("fixture: move sealed image failed")
		}
		if err := os.Mkdir(sealed, 0o700); err != nil {
			t.Fatal("fixture: plant invalid image failed")
		}

		other := randomFixture(t, "fixture-other-")
		if err := sv.put(t, fixtureIntegrationB, fixtureAbsentScope, other); !errors.Is(err, vault.ErrStorage) {
			t.Fatal("vault: write over invalid image not reported as storage failure")
		}
		mustDenyLocked(t, sv.v, "after storage failure")
		mustNotRelease(t, sv, secret.ErrLocked)
		if err := sv.unlock(t, sv.pass); !errors.Is(err, vault.ErrStorage) {
			t.Fatal("vault: unlock of invalid image not reported as storage failure")
		}
		mustDenyLocked(t, sv.v, "after invalid-image unlock")
		sv.restart(t)
		mustDenyLocked(t, sv.v, "after restart on invalid image")

		got := rec.since(n)
		// Operator events carry no integration for unseal; put carries B.
		mustDecisions(t, got, []decision{
			{audit.ActionVaultSecretPut, audit.OutcomeAllowed, idB},
			{audit.ActionVaultSecretPut, audit.OutcomeError, idB},
			{audit.ActionSecretAccess, audit.OutcomeDenied, idA}, // mustDenyLocked
			{audit.ActionSecretAccess, audit.OutcomeDenied, idA}, // mustNotRelease
			{audit.ActionVaultUnseal, audit.OutcomeError, audit.ID{}},
			{audit.ActionSecretAccess, audit.OutcomeDenied, idA}, // after unlock
			{audit.ActionSecretAccess, audit.OutcomeDenied, idA}, // after restart
		})
		for _, e := range got {
			if e.Action == audit.ActionSecretAccess && e.Outcome == audit.OutcomeAllowed {
				t.Fatal("audit: secret released after storage failure")
			}
		}
		rec.verifyAnchored(t, anchor)
		leakCheck(t, sv, rec, cred)
		assertNoLeak(t, nil, []string{other}, sv.dir, filepath.Dir(rec.path))
	})
}
