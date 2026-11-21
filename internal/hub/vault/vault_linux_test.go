//go:build linux

package vault

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hndrxc/hx/internal/hub/audit"
	"github.com/hndrxc/hx/internal/secret"
)

const (
	testPass    = "correct horse battery staple v1"
	testNewPass = "rotated passphrase for vault v2"
	testWrong   = "definitely not the passphrase"
	secretA     = "integration-token-AAAA-plaintext"
	secretB     = "integration-token-BBBB-plaintext"
	secretC     = "integration-token-CCCC-plaintext"
)

var operator = audit.ID{0x01, 0x02, 0x03}

// toggleLog wraps a real audit.Log and can inject appender failures.
type toggleLog struct {
	mu     sync.Mutex
	log    *audit.Log
	fail   bool
	events []audit.Event
}

var errInjected = errors.New("injected appender failure")

func (t *toggleLog) Append(e audit.Event) (audit.Checkpoint, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fail {
		return audit.Checkpoint{}, errInjected
	}
	cp, err := t.log.Append(e)
	if err == nil {
		t.events = append(t.events, e)
	}
	return cp, err
}

func (t *toggleLog) setFail(f bool) {
	t.mu.Lock()
	t.fail = f
	t.mu.Unlock()
}

func (t *toggleLog) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.events)
}

type fixture struct {
	dir      string
	auditDir string
	audit    *toggleLog
	v        *Vault
}

func vaultTestDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "vault")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: vaultTestDir(t), auditDir: vaultTestDir(t)}
	l, err := audit.Open(filepath.Join(f.auditDir, "audit.log"), audit.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f.audit = &toggleLog{log: l}
	t.Cleanup(func() { _ = l.Close() })
	f.open(t)
	return f
}

func (f *fixture) open(t *testing.T) {
	t.Helper()
	v, err := Open(f.dir, audit.NewHooks(f.audit))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	f.v = v
	t.Cleanup(func() { _ = v.Close() })
}

func (f *fixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	f.open(t)
}

func val(t *testing.T, s string) *secret.Value {
	t.Helper()
	v, err := secret.FromBytes([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func put(t *testing.T, v *Vault, in secret.IntegrationID, sc secret.Scope, s string) {
	t.Helper()
	x := val(t, s)
	defer x.Destroy()
	if err := v.Put(context.Background(), operator, in, sc, x); err != nil {
		t.Fatalf("Put %s/%s: %v", in, sc, err)
	}
}

func readSecret(t *testing.T, v *Vault, in secret.IntegrationID, sc secret.Scope) (string, error) {
	t.Helper()
	x, err := v.Open(context.Background(), in, sc)
	if err != nil {
		if x != nil {
			t.Fatalf("Open %s/%s returned value with error %v", in, sc, err)
		}
		return "", err
	}
	defer x.Destroy()
	var out string
	if err := x.Use(func(p []byte) error { out = string(p); return nil }); err != nil {
		t.Fatal(err)
	}
	return out, nil
}

func mustRead(t *testing.T, v *Vault, in secret.IntegrationID, sc secret.Scope, want string) {
	t.Helper()
	got, err := readSecret(t, v, in, sc)
	if err != nil {
		t.Fatalf("Open %s/%s: %v", in, sc, err)
	}
	if got != want {
		t.Fatalf("Open %s/%s: wrong value", in, sc)
	}
}

func mustMissing(t *testing.T, v *Vault, in secret.IntegrationID, sc secret.Scope) {
	t.Helper()
	if _, err := readSecret(t, v, in, sc); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("Open %s/%s: want ErrNotFound, got %v", in, sc, err)
	}
}

func mustLocked(t *testing.T, v *Vault) {
	t.Helper()
	if !v.Locked() {
		t.Fatal("vault unexpectedly unlocked")
	}
	if _, err := readSecret(t, v, "github", "token"); !errors.Is(err, secret.ErrLocked) {
		t.Fatalf("locked Open: want ErrLocked, got %v", err)
	}
}

func (f *fixture) initialize(t *testing.T, pass string) {
	t.Helper()
	p := val(t, pass)
	defer p.Destroy()
	if err := f.v.initialize(context.Background(), operator, p); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if f.v.Locked() {
		t.Fatal("vault locked after initialize")
	}
}

func (f *fixture) unlock(t *testing.T, pass string) error {
	t.Helper()
	p := val(t, pass)
	defer p.Destroy()
	return f.v.unlock(context.Background(), operator, p)
}

func (f *fixture) rotate(t *testing.T, pass string) error {
	t.Helper()
	p := val(t, pass)
	defer p.Destroy()
	return f.v.rotate(context.Background(), operator, p)
}

// restore locks the vault, restores raw, and requires the vault to stay
// locked whatever the outcome.
func (f *fixture) restore(t *testing.T, pass string, raw []byte) error {
	t.Helper()
	if !f.v.Locked() {
		if err := f.v.Lock(context.Background(), operator); err != nil {
			t.Fatalf("Lock: %v", err)
		}
	}
	p := val(t, pass)
	defer p.Destroy()
	err := f.v.restore(context.Background(), operator, p, raw)
	mustLocked(t, f.v)
	return err
}

func (f *fixture) backup(t *testing.T) []byte {
	t.Helper()
	raw, err := f.v.Backup(context.Background(), operator)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	return raw
}

// assertNoPlaintext scans every file under dirs and the provided captured
// output for any secret or passphrase bytes.
func assertNoPlaintext(t *testing.T, captured []byte, dirs ...string) {
	t.Helper()
	needles := []string{testPass, testNewPass, testWrong, secretA, secretB, secretC}
	check := func(where string, b []byte) {
		for _, n := range needles {
			if bytes.Contains(b, []byte(n)) {
				t.Fatalf("plaintext leaked into %s", where)
			}
		}
	}
	check("captured output", captured)
	for _, d := range dirs {
		err := filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			check(p, b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// captureOutput redirects stdout, stderr, the std logger and slog default
// while fn runs and returns everything written.
func captureOutput(t *testing.T, fn func()) []byte {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	oldLog, oldSlog := log.Writer(), slog.Default()
	os.Stdout, os.Stderr = w, w
	log.SetOutput(w)
	slog.SetDefault(slog.New(slog.NewTextHandler(w, nil)))
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	defer func() {
		os.Stdout, os.Stderr = oldOut, oldErr
		log.SetOutput(oldLog)
		slog.SetDefault(oldSlog)
	}()
	fn()
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

func sealedPath(dir string) string { return filepath.Join(dir, "vault.sealed") }

func TestOpenRefusesNonPrivateOrMissingDir(t *testing.T) {
	hooks := audit.NewHooks(&toggleLog{})
	if _, err := Open(filepath.Join(t.TempDir(), "missing"), hooks); err == nil {
		t.Fatal("Open accepted a missing directory")
	}
	d := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(d, hooks); err == nil {
		t.Fatal("Open accepted a group/world-accessible directory")
	}
}

func TestLockedStartupAndLifecycle(t *testing.T) {
	f := newFixture(t)
	mustLocked(t, f.v)
	if _, err := f.v.Backup(context.Background(), operator); err == nil {
		t.Fatal("Backup succeeded on uninitialized vault")
	}

	f.initialize(t, testPass)
	if _, err := os.Stat(sealedPath(f.dir)); err != nil {
		t.Fatalf("vault.sealed missing after initialize: %v", err)
	}
	p := val(t, testPass)
	if err := f.v.initialize(context.Background(), operator, p); err == nil {
		t.Fatal("second initialize succeeded")
	}
	p.Destroy()

	put(t, f.v, "github", "token", secretA)
	put(t, f.v, "github", "webhook", secretB)
	mustRead(t, f.v, "github", "token", secretA)
	put(t, f.v, "github", "token", secretC) // upsert
	mustRead(t, f.v, "github", "token", secretC)

	// Restart: always starts locked even with a valid sealed file.
	f.reopen(t)
	mustLocked(t, f.v)
	x := val(t, secretA)
	if err := f.v.Put(context.Background(), operator, "github", "token", x); err == nil {
		t.Fatal("Put succeeded while locked")
	}
	x.Destroy()
	if err := f.v.Delete(context.Background(), operator, "github", "token"); err == nil {
		t.Fatal("Delete succeeded while locked")
	}

	if err := f.unlock(t, testWrong); err == nil {
		t.Fatal("unlock with wrong passphrase succeeded")
	}
	mustLocked(t, f.v)

	if err := f.unlock(t, testPass); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	mustRead(t, f.v, "github", "token", secretC)
	mustRead(t, f.v, "github", "webhook", secretB)

	if err := f.v.Delete(context.Background(), operator, "github", "webhook"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	mustMissing(t, f.v, "github", "webhook")

	if err := f.v.Lock(context.Background(), operator); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	mustLocked(t, f.v)

	f.reopen(t)
	if err := f.unlock(t, testPass); err != nil {
		t.Fatalf("unlock after reopen: %v", err)
	}
	mustRead(t, f.v, "github", "token", secretC)
	mustMissing(t, f.v, "github", "webhook")
	assertNoPlaintext(t, nil, f.dir, f.auditDir)
}

func TestScopedHandles(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, testPass)
	put(t, f.v, "github", "token", secretA)
	put(t, f.v, "github", "webhook", secretB)
	put(t, f.v, "slack", "token", secretC)

	h, err := secret.NewHandle(f.v, "github", "token")
	if err != nil {
		t.Fatal(err)
	}
	var got string
	if err := h.Use(context.Background(), "token", func(p []byte) error { got = string(p); return nil }); err != nil {
		t.Fatalf("Handle.Use: %v", err)
	}
	if got != secretA {
		t.Fatal("handle returned wrong integration/scope value")
	}
	called := false
	err = h.Use(context.Background(), "webhook", func([]byte) error { called = true; return nil })
	if !errors.Is(err, secret.ErrScopeNotDeclared) || called {
		t.Fatalf("undeclared scope: want ErrScopeNotDeclared without callback, got %v", err)
	}
	missing, err := secret.NewHandle(f.v, "github", "absent")
	if err != nil {
		t.Fatal(err)
	}
	if err := missing.Use(context.Background(), "absent", func([]byte) error { called = true; return nil }); !errors.Is(err, secret.ErrNotFound) || called {
		t.Fatalf("missing scope: want ErrNotFound without callback, got %v", err)
	}
	mustRead(t, f.v, "slack", "token", secretC)
	mustMissing(t, f.v, "slack", "webhook")

	if err := f.v.Lock(context.Background(), operator); err != nil {
		t.Fatal(err)
	}
	if err := h.Use(context.Background(), "token", func([]byte) error { called = true; return nil }); !errors.Is(err, secret.ErrLocked) || called {
		t.Fatalf("locked handle: want ErrLocked without callback, got %v", err)
	}
}

func TestCorruptionFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, testPass)
	put(t, f.v, "github", "token", secretA)
	if err := f.v.Close(); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(sealedPath(f.dir))
	if err != nil {
		t.Fatal(err)
	}
	positions := []int{0, len(orig) / 4, len(orig) / 2, len(orig) - 1}
	for _, pos := range positions {
		c := bytes.Clone(orig)
		c[pos] ^= 0x40
		if err := os.WriteFile(sealedPath(f.dir), c, 0o600); err != nil {
			t.Fatal(err)
		}
		f.open(t)
		if err := f.unlock(t, testPass); err == nil {
			t.Fatalf("unlock accepted corruption at byte %d", pos)
		}
		mustLocked(t, f.v)
		_ = f.v.Close()
	}
	for _, c := range [][]byte{orig[:len(orig)/2], {}} {
		if err := os.WriteFile(sealedPath(f.dir), c, 0o600); err != nil {
			t.Fatal(err)
		}
		v, err := Open(f.dir, audit.NewHooks(f.audit))
		if err != nil {
			continue // refusing to open a truncated store is also fail-closed
		}
		f.v = v
		if err := f.unlock(t, testPass); err == nil {
			t.Fatal("unlock accepted truncated store")
		}
		mustLocked(t, f.v)
		_ = v.Close()
	}
	// The original bytes still unlock: corruption handling never rewrote the store.
	if err := os.WriteFile(sealedPath(f.dir), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	if err := f.unlock(t, testPass); err != nil {
		t.Fatalf("unlock original: %v", err)
	}
	mustRead(t, f.v, "github", "token", secretA)
}

func TestAppenderFailureDeniesWithoutGrant(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, testPass)
	put(t, f.v, "github", "token", secretA)
	if err := f.v.Lock(context.Background(), operator); err != nil {
		t.Fatal(err)
	}

	f.audit.setFail(true)
	if err := f.unlock(t, testPass); err == nil {
		t.Fatal("unlock granted while audit appender fails")
	}
	if !f.v.Locked() {
		t.Fatal("vault unlocked despite audit failure")
	}

	f.audit.setFail(false)
	if err := f.unlock(t, testPass); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	f.audit.setFail(true)
	x, err := f.v.Open(context.Background(), "github", "token")
	if err == nil || x != nil {
		if x != nil {
			x.Destroy()
		}
		t.Fatal("secret access granted while audit appender fails")
	}
	h, err := secret.NewHandle(f.v, "github", "token")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := h.Use(context.Background(), "token", func([]byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("handle granted plaintext while audit appender fails")
	}
	f.audit.setFail(false)
	mustRead(t, f.v, "github", "token", secretA)
	if f.audit.count() == 0 {
		t.Fatal("no audit events recorded")
	}
	assertNoPlaintext(t, nil, f.dir, f.auditDir)
}

func TestAuditChainVerifies(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, testPass)
	put(t, f.v, "github", "token", secretA)
	mustRead(t, f.v, "github", "token", secretA)
	if err := f.v.Lock(context.Background(), operator); err != nil {
		t.Fatal(err)
	}
	_ = f.unlock(t, testWrong)
	if err := f.unlock(t, testPass); err != nil {
		t.Fatal(err)
	}
	r, err := os.Open(filepath.Join(f.auditDir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cp, err := audit.Verify(r, nil)
	if err != nil {
		t.Fatalf("audit chain: %v", err)
	}
	if cp.Sequence != uint64(f.audit.count()) {
		t.Fatalf("audit sequence %d, recorded %d", cp.Sequence, f.audit.count())
	}
	var sawDenied, sawAccess bool
	for _, e := range f.audit.events {
		if e.ActorID != operator && e.Action == audit.ActionVaultUnseal {
			t.Fatal("unseal event not attributed to operator")
		}
		sawDenied = sawDenied || (e.Action == audit.ActionVaultUnseal && e.Outcome != audit.OutcomeAllowed)
		sawAccess = sawAccess || (e.Action == audit.ActionSecretAccess && e.Outcome == audit.OutcomeAllowed)
	}
	if !sawDenied || !sawAccess {
		t.Fatal("missing denied unseal or allowed secret access events")
	}
}

func TestBackupRestoreRepeatableCompleteSnapshot(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, testPass)
	put(t, f.v, "github", "token", secretA)
	put(t, f.v, "github", "webhook", secretB)
	b1 := f.backup(t)
	b1again := f.backup(t)
	if len(b1) == 0 || len(b1again) == 0 {
		t.Fatal("empty backup")
	}

	put(t, f.v, "github", "token", secretC)
	if err := f.v.Delete(context.Background(), operator, "github", "webhook"); err != nil {
		t.Fatal(err)
	}
	put(t, f.v, "slack", "token", secretA)
	b2 := f.backup(t)

	for i := range 2 { // repeatable
		if err := f.restore(t, testPass, b1); err != nil {
			t.Fatalf("restore b1 #%d: %v", i, err)
		}
		mustLocked(t, f.v)
		if err := f.unlock(t, testPass); err != nil {
			t.Fatal(err)
		}
		mustRead(t, f.v, "github", "token", secretA)
		mustRead(t, f.v, "github", "webhook", secretB)
		mustMissing(t, f.v, "slack", "token")
	}
	if err := f.restore(t, testPass, b1again); err != nil {
		t.Fatalf("restore second b1 copy: %v", err)
	}

	if err := f.restore(t, testPass, b2); err != nil {
		t.Fatalf("restore b2: %v", err)
	}
	f.reopen(t)
	mustLocked(t, f.v)
	if err := f.unlock(t, testPass); err != nil {
		t.Fatal(err)
	}
	mustRead(t, f.v, "github", "token", secretC)
	mustMissing(t, f.v, "github", "webhook")
	mustRead(t, f.v, "slack", "token", secretA)

	// Corrupt or wrong-pass restore leaves the current store intact.
	bad := bytes.Clone(b1)
	bad[len(bad)/2] ^= 0x01
	if err := f.restore(t, testPass, bad); err == nil {
		t.Fatal("restore accepted corrupted backup")
	}
	if err := f.restore(t, testWrong, b1); err == nil {
		t.Fatal("restore accepted wrong passphrase")
	}
	f.reopen(t)
	if err := f.unlock(t, testPass); err != nil {
		t.Fatal(err)
	}
	mustRead(t, f.v, "github", "token", secretC)
	mustRead(t, f.v, "slack", "token", secretA)
	assertNoPlaintext(t, append(append(bytes.Clone(b1), b2...), bad...), f.dir, f.auditDir)
}

func TestRestoreRefusedWhileUnlocked(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, testPass)
	put(t, f.v, "github", "token", secretA)
	b := f.backup(t)
	p := val(t, testPass)
	defer p.Destroy()
	if err := f.v.restore(context.Background(), operator, p, b); !errors.Is(err, ErrUnlocked) {
		t.Fatalf("restore while unlocked: want ErrUnlocked, got %v", err)
	}
}

// A disk fault before the rename (temp fsync) leaves the prior snapshot
// published and the vault locked.
func TestRestorePreRenameFaultKeepsPriorSnapshot(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, testPass)
	put(t, f.v, "github", "token", secretA)
	old := f.backup(t)
	put(t, f.v, "github", "token", secretB)

	boom := errors.New("injected fsync fault")
	f.v.disk.fsync = func(int) error { return boom }
	if err := f.restore(t, testPass, old); !errors.Is(err, ErrStorage) || !errors.Is(err, boom) {
		t.Fatalf("restore with temp fsync fault: want ErrStorage+fault, got %v", err)
	}
	f.reopen(t)
	if err := f.unlock(t, testPass); err != nil {
		t.Fatal(err)
	}
	mustRead(t, f.v, "github", "token", secretB)
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempPrefix) {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestRotationAndRecovery(t *testing.T) {
	f := newFixture(t)
	f.initialize(t, testPass)
	put(t, f.v, "github", "token", secretA)
	old := f.backup(t)

	if err := f.rotate(t, testNewPass); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	put(t, f.v, "github", "webhook", secretB)
	newer := f.backup(t)

	f.reopen(t)
	if err := f.unlock(t, testPass); err == nil {
		t.Fatal("old passphrase unlocks rotated store")
	}
	if err := f.unlock(t, testNewPass); err != nil {
		t.Fatalf("unlock with rotated passphrase: %v", err)
	}
	mustRead(t, f.v, "github", "token", secretA)
	mustRead(t, f.v, "github", "webhook", secretB)

	// Old backup recovers only with its corresponding old passphrase and
	// restores the complete old snapshot.
	if err := f.restore(t, testNewPass, old); err == nil {
		t.Fatal("old backup restored with new passphrase")
	}
	if err := f.restore(t, testPass, old); err != nil {
		t.Fatalf("restore old backup: %v", err)
	}
	f.reopen(t)
	if err := f.unlock(t, testNewPass); err == nil {
		t.Fatal("new passphrase unlocks restored old snapshot")
	}
	if err := f.unlock(t, testPass); err != nil {
		t.Fatal(err)
	}
	mustRead(t, f.v, "github", "token", secretA)
	mustMissing(t, f.v, "github", "webhook")

	// New backup restores the complete new snapshot under the new passphrase.
	if err := f.restore(t, testPass, newer); err == nil {
		t.Fatal("new backup restored with old passphrase")
	}
	if err := f.restore(t, testNewPass, newer); err != nil {
		t.Fatalf("restore new backup: %v", err)
	}
	f.reopen(t)
	if err := f.unlock(t, testNewPass); err != nil {
		t.Fatal(err)
	}
	mustRead(t, f.v, "github", "token", secretA)
	mustRead(t, f.v, "github", "webhook", secretB)

	// Rotation denied by audit failure keeps the previous passphrase valid.
	f.audit.setFail(true)
	if err := f.rotate(t, testPass); err == nil {
		t.Fatal("rotation succeeded while audit appender fails")
	}
	f.audit.setFail(false)
	f.reopen(t)
	if err := f.unlock(t, testNewPass); err != nil {
		t.Fatalf("passphrase changed by failed rotation: %v", err)
	}
	assertNoPlaintext(t, append(bytes.Clone(old), newer...), f.dir, f.auditDir)
}

func TestNoSensitiveOutput(t *testing.T) {
	f := newFixture(t)
	out := captureOutput(t, func() {
		f.initialize(t, testPass)
		put(t, f.v, "github", "token", secretA)
		_ = f.unlock(t, testWrong)
		mustRead(t, f.v, "github", "token", secretA)
		b := f.backup(t)
		_ = f.rotate(t, testNewPass)
		_ = f.restore(t, testWrong, b)
		_ = f.v.Lock(context.Background(), operator)
		_ = f.unlock(t, testWrong)
	})
	assertNoPlaintext(t, out, f.dir, f.auditDir)
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s is group/world accessible: %v", e.Name(), info.Mode())
		}
	}
}

func TestTerminalAdapterRefusesPipes(t *testing.T) {
	f := newFixture(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go func() {
		_, _ = io.WriteString(w, testPass+"\n"+testPass+"\n")
		_ = w.Close()
	}()
	var prompt bytes.Buffer
	p := secret.TerminalPrompter{In: r, Out: &prompt}
	ctx := context.Background()

	if err := f.v.PromptInitialize(ctx, operator, p); !errors.Is(err, secret.ErrNotTerminal) {
		t.Fatalf("PromptInitialize: want ErrNotTerminal, got %v", err)
	}
	if _, err := os.Stat(sealedPath(f.dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("piped PromptInitialize created a store")
	}
	f.initialize(t, testPass)
	b := f.backup(t)
	if err := f.v.Lock(ctx, operator); err != nil {
		t.Fatal(err)
	}
	if err := f.v.PromptUnlock(ctx, operator, p); !errors.Is(err, secret.ErrNotTerminal) {
		t.Fatalf("PromptUnlock: want ErrNotTerminal, got %v", err)
	}
	mustLocked(t, f.v)
	if err := f.unlock(t, testPass); err != nil {
		t.Fatal(err)
	}
	if err := f.v.PromptRotate(ctx, operator, p); !errors.Is(err, secret.ErrNotTerminal) {
		t.Fatalf("PromptRotate: want ErrNotTerminal, got %v", err)
	}
	if err := f.v.PromptRestore(ctx, operator, p, b); !errors.Is(err, secret.ErrNotTerminal) {
		t.Fatalf("PromptRestore: want ErrNotTerminal, got %v", err)
	}
	f.reopen(t)
	if err := f.unlock(t, testPass); err != nil {
		t.Fatalf("piped prompts altered passphrase: %v", err)
	}
	assertNoPlaintext(t, prompt.Bytes(), f.dir, f.auditDir)
}
