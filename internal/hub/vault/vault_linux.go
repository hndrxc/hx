//go:build linux

// Package vault is the hub's encrypted secret vault. It is owned by the
// trusted hub: clients never receive a *Vault or secret values; the hub
// opens secrets only on behalf of integrations, which receive handles.
// Passphrases enter only through an interactive terminal prompter.
package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io/fs"
	"log/slog"
	"sync"
	"time"

	"github.com/hndrxc/hx/internal/hub/audit"
	"github.com/hndrxc/hx/internal/secret"
)

var (
	// ErrAlreadyInitialized reports an initialize over an existing image.
	ErrAlreadyInitialized = errors.New("vault: already initialized")
	// ErrUnlocked reports an operation that requires a locked vault.
	ErrUnlocked = errors.New("vault: unlocked")
	// ErrNotInitialized reports that no sealed image exists.
	ErrNotInitialized = errors.New("vault: not initialized")
	// ErrClosed reports use after Close.
	ErrClosed = errors.New("vault: closed")
	// ErrInvalidActor reports a missing verified operator identity.
	ErrInvalidActor = errors.New("vault: invalid operator identity")
	// ErrPassphraseMismatch reports a failed passphrase confirmation.
	ErrPassphraseMismatch = errors.New("vault: passphrases do not match")
	// ErrStorage reports a failure reading or persisting the sealed image.
	ErrStorage = errors.New("vault: storage failure")
)

const (
	labelPassphrase = "Vault passphrase"
	labelNew        = "New vault passphrase"
	labelConfirm    = "Confirm vault passphrase"
)

// Vault holds, while unlocked, only the protected DEK and the sealed
// envelope (ciphertext). It starts locked and reads nothing at Open.
type Vault struct {
	mu     sync.Mutex
	disk   *disk
	hooks  audit.Hooks
	env    *envelope     // nil while locked
	dek    *secret.Value // nil while locked
	closed bool
	now    func() time.Time
}

// Open anchors dir and returns a locked vault. It does not read or require
// a sealed image.
func Open(dir string, hooks audit.Hooks) (*Vault, error) {
	d, err := openDisk(dir)
	if err != nil {
		return nil, err
	}
	return &Vault{disk: d, hooks: hooks, now: time.Now}, nil
}

func (v *Vault) String() string       { return "vault.Vault" }
func (v *Vault) GoString() string     { return "vault.Vault" }
func (v *Vault) LogValue() slog.Value { return slog.StringValue("vault.Vault") }

// Close erases the key and releases the directory lock.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.eraseLocked()
	if v.closed {
		return nil
	}
	v.closed = true
	return v.disk.close()
}

// Locked reports whether the vault holds no key.
func (v *Vault) Locked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.dek == nil
}

// eraseLocked drops the key and envelope; v.mu must be held.
func (v *Vault) eraseLocked() {
	v.dek.Destroy()
	v.dek = nil
	v.env = nil
}

// attempt carries one audited operation's verified metadata.
type attempt struct {
	v    *Vault
	meta audit.Meta
}

func newCorrelation() (audit.ID, error) {
	var id audit.ID
	if _, err := rand.Read(id[:]); err != nil {
		return audit.ID{}, err
	}
	return id, nil
}

// integrationID derives a stable pseudonymous audit ID from a validated
// integration name.
func integrationID(i secret.IntegrationID) audit.ID {
	h := sha256.New()
	h.Write([]byte("hx vault integration v1\x00"))
	h.Write([]byte(i))
	var id audit.ID
	copy(id[:], h.Sum(nil))
	return id
}

// operator starts an operator attempt. A zero actor is recorded as an
// unattributed denial and rejected.
func (v *Vault) operator(actor audit.ID, a audit.Action, integ audit.ID) (*attempt, error) {
	corr, err := newCorrelation()
	if err != nil {
		return nil, err
	}
	at := &attempt{v: v, meta: audit.Meta{ActorKind: audit.ActorOperator, ActorID: actor, IntegrationID: integ, CorrelationID: corr}}
	if actor.IsZero() {
		at.meta.ActorKind = audit.ActorUnknown
		at.meta.ActorID = corr
		_ = at.record(a, audit.OutcomeDenied)
		return nil, ErrInvalidActor
	}
	return at, nil
}

func (at *attempt) record(a audit.Action, o audit.Outcome) error {
	at.meta.At = at.v.now()
	switch a {
	case audit.ActionVaultUnseal:
		return at.v.hooks.VaultUnseal(at.meta, o)
	case audit.ActionSecretAccess:
		return at.v.hooks.SecretAccess(at.meta, o)
	default:
		return at.v.hooks.VaultLifecycle(a, at.meta, o)
	}
}

// fail records a denial or error (best effort) and returns err.
func (at *attempt) fail(a audit.Action, o audit.Outcome, err error) error {
	_ = at.record(a, o)
	return err
}

// classify maps an envelope/disk error to an audit outcome.
func classify(err error) audit.Outcome {
	if errors.Is(err, ErrAuthentication) || errors.Is(err, secret.ErrNotFound) {
		return audit.OutcomeDenied
	}
	return audit.OutcomeError
}

func (v *Vault) usable(at *attempt, a audit.Action) error {
	if v.closed {
		return at.fail(a, audit.OutcomeError, ErrClosed)
	}
	return nil
}

func (v *Vault) requireUnlocked(at *attempt, a audit.Action) error {
	if err := v.usable(at, a); err != nil {
		return err
	}
	if v.dek == nil {
		return at.fail(a, audit.OutcomeDenied, secret.ErrLocked)
	}
	return nil
}

func (v *Vault) requireLocked(at *attempt, a audit.Action) error {
	if err := v.usable(at, a); err != nil {
		return err
	}
	if v.dek != nil {
		return at.fail(a, audit.OutcomeDenied, ErrUnlocked)
	}
	return nil
}

// persist records the allowed intent, then publishes raw. A failed write is
// ambiguous: the vault locks and the error is recorded under the same
// correlation.
func (v *Vault) persist(ctx context.Context, at *attempt, a audit.Action, raw []byte) error {
	if err := ctx.Err(); err != nil {
		return at.fail(a, audit.OutcomeError, err)
	}
	if err := at.record(a, audit.OutcomeAllowed); err != nil {
		return err
	}
	if err := v.disk.write(raw); err != nil {
		v.eraseLocked()
		_ = at.record(a, audit.OutcomeError)
		return errors.Join(ErrStorage, err)
	}
	return nil
}

// Open implements secret.Source for the trusted hub. The caller owns and
// must destroy the returned value.
func (v *Vault) Open(ctx context.Context, integration secret.IntegrationID, scope secret.Scope) (*secret.Value, error) {
	k := key{integration: integration, scope: scope}
	if !validKey(k) {
		return nil, secret.ErrInvalidScope
	}
	const a = audit.ActionSecretAccess
	corr, err := newCorrelation()
	if err != nil {
		return nil, err
	}
	iid := integrationID(integration)
	at := &attempt{v: v, meta: audit.Meta{ActorKind: audit.ActorIntegration, ActorID: iid, IntegrationID: iid, CorrelationID: corr}}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(at, a); err != nil {
		return nil, err
	}
	val, err := v.env.open(v.dek, k)
	if err != nil {
		if errors.Is(err, ErrCorrupt) {
			v.eraseLocked()
		}
		return nil, at.fail(a, classify(err), err)
	}
	if err := ctx.Err(); err != nil {
		val.Destroy()
		return nil, at.fail(a, audit.OutcomeError, err)
	}
	if err := at.record(a, audit.OutcomeAllowed); err != nil {
		val.Destroy()
		return nil, err
	}
	return val, nil
}

// Put inserts or replaces the secret for integration/scope.
func (v *Vault) Put(ctx context.Context, actor audit.ID, integration secret.IntegrationID, scope secret.Scope, value *secret.Value) error {
	k := key{integration: integration, scope: scope}
	if !validKey(k) {
		return secret.ErrInvalidScope
	}
	return v.mutate(ctx, actor, audit.ActionVaultSecretPut, integrationID(integration), func(e *envelope) error {
		return e.put(v.dek, k, value)
	})
}

// Delete removes the secret for integration/scope.
func (v *Vault) Delete(ctx context.Context, actor audit.ID, integration secret.IntegrationID, scope secret.Scope) error {
	k := key{integration: integration, scope: scope}
	if !validKey(k) {
		return secret.ErrInvalidScope
	}
	return v.mutate(ctx, actor, audit.ActionVaultSecretDelete, integrationID(integration), func(e *envelope) error {
		return e.remove(k)
	})
}

// mutate applies fn to a clone of the envelope and publishes it.
func (v *Vault) mutate(ctx context.Context, actor audit.ID, a audit.Action, integ audit.ID, fn func(*envelope) error) error {
	at, err := v.operator(actor, a, integ)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(at, a); err != nil {
		return err
	}
	next := v.env.clone()
	if err := fn(next); err != nil {
		if errors.Is(err, ErrCorrupt) {
			v.eraseLocked()
		}
		return at.fail(a, classify(err), err)
	}
	raw, err := next.encode(v.dek)
	if err != nil {
		v.eraseLocked()
		return at.fail(a, audit.OutcomeError, err)
	}
	if err := v.persist(ctx, at, a, raw); err != nil {
		return err
	}
	v.env = next
	return nil
}

// Lock erases the key. The actor is validated first; an authenticated
// caller's key erasure always happens before, and regardless of, the audit
// record, which is written under the mutex so it orders with other state
// changes. A failed audit is returned so the caller fails closed.
func (v *Vault) Lock(ctx context.Context, actor audit.ID) error {
	const a = audit.ActionVaultLock
	at, err := v.operator(actor, a, audit.ID{})
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.eraseLocked()
	return at.record(a, audit.OutcomeAllowed)
}

// Backup returns the sealed image of an unlocked vault.
func (v *Vault) Backup(ctx context.Context, actor audit.ID) ([]byte, error) {
	const a = audit.ActionVaultBackup
	at, err := v.operator(actor, a, audit.ID{})
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(at, a); err != nil {
		return nil, err
	}
	raw, err := v.env.encode(v.dek)
	if err != nil {
		v.eraseLocked()
		return nil, at.fail(a, audit.OutcomeError, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, at.fail(a, audit.OutcomeError, err)
	}
	if err := at.record(a, audit.OutcomeAllowed); err != nil {
		return nil, err
	}
	return raw, nil
}

func (v *Vault) initialize(ctx context.Context, actor audit.ID, pass *secret.Value) error {
	const a = audit.ActionVaultInitialize
	at, err := v.operator(actor, a, audit.ID{})
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireLocked(at, a); err != nil {
		return err
	}
	switch _, err := v.disk.read(); {
	case err == nil:
		return at.fail(a, audit.OutcomeDenied, ErrAlreadyInitialized)
	case !errors.Is(err, fs.ErrNotExist):
		return at.fail(a, audit.OutcomeError, errors.Join(ErrStorage, err))
	}
	if err := ctx.Err(); err != nil {
		return at.fail(a, audit.OutcomeError, err)
	}
	env, dek, err := newEnvelope(pass)
	if err != nil {
		return at.fail(a, audit.OutcomeError, err)
	}
	raw, err := env.encode(dek)
	if err != nil {
		dek.Destroy()
		return at.fail(a, audit.OutcomeError, err)
	}
	if err := v.persist(ctx, at, a, raw); err != nil {
		dek.Destroy()
		return err
	}
	v.env, v.dek = env, dek
	return nil
}

func (v *Vault) unlock(ctx context.Context, actor audit.ID, pass *secret.Value) error {
	const a = audit.ActionVaultUnseal
	at, err := v.operator(actor, a, audit.ID{})
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireLocked(at, a); err != nil {
		return err
	}
	raw, err := v.disk.read()
	if errors.Is(err, fs.ErrNotExist) {
		return at.fail(a, audit.OutcomeDenied, ErrNotInitialized)
	}
	if err != nil {
		return at.fail(a, audit.OutcomeError, errors.Join(ErrStorage, err))
	}
	env, err := decodeEnvelope(raw)
	if err != nil {
		return at.fail(a, audit.OutcomeError, err)
	}
	if err := ctx.Err(); err != nil {
		return at.fail(a, audit.OutcomeError, err)
	}
	dek, err := env.unlock(pass)
	if err != nil {
		return at.fail(a, classify(err), err)
	}
	if err := ctx.Err(); err != nil {
		dek.Destroy()
		return at.fail(a, audit.OutcomeError, err)
	}
	if err := at.record(a, audit.OutcomeAllowed); err != nil {
		dek.Destroy()
		return err
	}
	v.env, v.dek = env, dek
	return nil
}

// rotate re-encrypts every record under a fresh key wrapped by pass. Until
// the write is attempted the old envelope and key stay in place; an
// ambiguous write failure locks the vault (via persist).
func (v *Vault) rotate(ctx context.Context, actor audit.ID, pass *secret.Value) error {
	const a = audit.ActionVaultRotate
	at, err := v.operator(actor, a, audit.ID{})
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireUnlocked(at, a); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return at.fail(a, audit.OutcomeError, err)
	}
	next, dek, err := v.env.rekey(v.dek, pass)
	if err != nil {
		if errors.Is(err, ErrCorrupt) {
			v.eraseLocked()
		}
		return at.fail(a, audit.OutcomeError, err)
	}
	raw, err := next.encode(dek)
	if err != nil {
		dek.Destroy()
		return at.fail(a, audit.OutcomeError, err)
	}
	if err := v.persist(ctx, at, a, raw); err != nil {
		dek.Destroy()
		return err
	}
	v.dek.Destroy()
	v.env, v.dek = next, dek
	return nil
}

// restore validates raw under pass and publishes it. The vault must be
// locked and stays locked on success and failure; a corrupt current image
// may be replaced.
func (v *Vault) restore(ctx context.Context, actor audit.ID, pass *secret.Value, raw []byte) error {
	const a = audit.ActionVaultRestore
	at, err := v.operator(actor, a, audit.ID{})
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireLocked(at, a); err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > maxImage {
		return at.fail(a, audit.OutcomeError, ErrCorrupt)
	}
	img := append([]byte(nil), raw...) // immune to caller mutation after validation
	env, err := decodeEnvelope(img)
	if err != nil {
		return at.fail(a, audit.OutcomeError, err)
	}
	dek, err := env.unlock(pass)
	if err != nil {
		return at.fail(a, classify(err), err)
	}
	dek.Destroy()
	return v.persist(ctx, at, a, img)
}

// prompt reads one passphrase, or two with confirmation.
func prompt(ctx context.Context, p secret.TerminalPrompter, label string, confirm bool) (*secret.Value, error) {
	pass, err := p.PromptSecret(ctx, label)
	if err != nil {
		return nil, err
	}
	if !confirm {
		return pass, nil
	}
	again, err := p.PromptSecret(ctx, labelConfirm)
	if err != nil {
		pass.Destroy()
		return nil, err
	}
	defer again.Destroy()
	match := false
	err = pass.Use(func(x []byte) error {
		return again.Use(func(y []byte) error {
			match = subtle.ConstantTimeCompare(x, y) == 1
			return nil
		})
	})
	if err != nil || !match {
		pass.Destroy()
		if err == nil {
			err = ErrPassphraseMismatch
		}
		return nil, err
	}
	return pass, nil
}

// PromptInitialize creates a new vault from a confirmed terminal passphrase
// and leaves it unlocked.
func (v *Vault) PromptInitialize(ctx context.Context, actor audit.ID, p secret.TerminalPrompter) error {
	pass, err := prompt(ctx, p, labelNew, true)
	if err != nil {
		return err
	}
	defer pass.Destroy()
	return v.initialize(ctx, actor, pass)
}

// PromptUnlock unlocks the vault with a terminal passphrase.
func (v *Vault) PromptUnlock(ctx context.Context, actor audit.ID, p secret.TerminalPrompter) error {
	pass, err := prompt(ctx, p, labelPassphrase, false)
	if err != nil {
		return err
	}
	defer pass.Destroy()
	return v.unlock(ctx, actor, pass)
}

// PromptRotate rewraps the key under a confirmed new terminal passphrase.
func (v *Vault) PromptRotate(ctx context.Context, actor audit.ID, p secret.TerminalPrompter) error {
	pass, err := prompt(ctx, p, labelNew, true)
	if err != nil {
		return err
	}
	defer pass.Destroy()
	return v.rotate(ctx, actor, pass)
}

// PromptRestore replaces the sealed image with raw after validating it
// under a terminal passphrase. The vault remains locked.
func (v *Vault) PromptRestore(ctx context.Context, actor audit.ID, p secret.TerminalPrompter, raw []byte) error {
	pass, err := prompt(ctx, p, labelPassphrase, false)
	if err != nil {
		return err
	}
	defer pass.Destroy()
	return v.restore(ctx, actor, pass, raw)
}
