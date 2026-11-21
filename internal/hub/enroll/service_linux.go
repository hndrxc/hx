//go:build linux

package enroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/hndrxc/hx/internal/hub/audit"
)

// ID is the stable identifier of an enrolled client; it is also the audit
// actor identity of that client.
type ID = audit.ID

// Role is the single right granted to an enrolled client.
type Role uint8

const (
	// RoleRead clients (tag:hx-client) may read.
	RoleRead Role = 1
	// RoleIngest clients (tag:hx-agent) may ingest for their own ID.
	RoleIngest Role = 2
)

// Action is an operation requested of the service.
type Action uint8

const (
	ActionRead   Action = 1
	ActionIngest Action = 2
	ActionAdmin  Action = 3
)

const (
	tagClient = "tag:hx-client"
	tagAgent  = "tag:hx-agent"

	maxIdentifier = 256
	maxPending    = 1024
	pendingTTL    = 5 * time.Minute
)

// Binding is the exact Tailscale identity a client is bound to.
type Binding struct {
	NodeID string
	UserID string
	Tag    string
}

// TailnetPeer is a remote caller as reported by the verified WhoIs of the
// transport adapter. It is never decoded from a peer payload.
type TailnetPeer struct {
	NodeID string
	UserID string
	Tags   []string
}

// LocalPeer is a local caller as verified by the local transport adapter.
type LocalPeer struct {
	ID       ID
	Operator bool
}

// Credential is the result of a successful enrollment or renewal.
type Credential struct {
	ID             ID
	CertificateDER []byte
	RootDER        []byte
}

type record struct {
	ID          ID
	Role        Role
	Binding     Binding
	Fingerprint [32]byte
}

// Errors are fixed categories; they never carry caller input.
var (
	ErrDenied      = errors.New("enroll: denied")
	ErrExpired     = errors.New("enroll: expired")
	ErrUnavailable = errors.New("enroll: unavailable")
)

const redacted = "[redacted]"

// Token is an opaque one-time approval secret. Its formatting, slog and JSON
// representations are redacted.
type Token struct{ b [32]byte }

// ParseToken builds a Token from exactly 32 bytes received over a trusted
// transport.
func ParseToken(b []byte) (Token, error) {
	var t Token
	if len(b) != len(t.b) {
		return Token{}, ErrDenied
	}
	copy(t.b[:], b)
	if t.b == ([32]byte{}) {
		return Token{}, ErrDenied
	}
	return t, nil
}

// Bytes returns the raw token for the trusted transport only.
func (t Token) Bytes() [32]byte { return t.b }

func (Token) String() string               { return redacted }
func (Token) GoString() string             { return redacted }
func (Token) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }
func (Token) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Token) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Token) MarshalText() ([]byte, error) { return []byte(redacted), nil }

type pending struct {
	binding Binding
	role    Role
	csrHash [32]byte
	expires time.Time
}

// Service is the client enrollment state machine. A single mutex serializes
// all state and crypto so tokens are single-use and rights never race.
//
// Audit semantics: allowed outcomes are recorded before any grant or
// publication; if that record fails the operation is denied and nothing is
// published. Denials and errors are recorded best effort and never grant.
// A failed durable save is ambiguous: the in-memory change is rolled back,
// an error event is recorded, and the instance refuses all calls until it is
// closed and reopened from disk.
type Service struct {
	mu        sync.Mutex
	disk      *registryDisk
	authority *Authority
	hooks     audit.Hooks
	records   map[ID]record
	pending   map[[32]byte]pending
	now       func() time.Time
	unusable  bool
	closed    bool
}

// Open loads the registry in dir. openRegistry validates every record and
// the entry cap; authority must come from NewAuthority.
func Open(dir string, authority *Authority, hooks audit.Hooks) (*Service, error) {
	if authority == nil || authority.root == nil || authority.pool == nil || authority.key == nil {
		return nil, ErrUnavailable
	}
	disk, records, err := openRegistry(dir)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Service{
		disk:      disk,
		authority: authority,
		hooks:     hooks,
		records:   records,
		pending:   make(map[[32]byte]pending),
		now:       time.Now,
	}, nil
}

// Close releases the registry. Pending approvals are discarded.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.pending = nil
	if err := s.disk.close(); err != nil {
		return ErrUnavailable
	}
	return nil
}

// Approve creates a one-time token for binding and role, bound to the exact
// CSR. Only a verified local operator may approve.
func (s *Service) Approve(ctx context.Context, operator LocalPeer, binding Binding, role Role, csrDER []byte) (Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.ready(ctx) {
		return Token{}, ErrUnavailable
	}
	if !verifiedOperator(operator) {
		s.deny(s.hooks.ClientEnrollment, now)
		return Token{}, ErrDenied
	}
	if !validBinding(binding, role) {
		s.denyAs(s.hooks.ClientEnrollment, now, audit.ActorOperator, operator.ID)
		return Token{}, ErrDenied
	}
	// parseCSR bounds csrDER before it is hashed below.
	if _, err := parseCSR(csrDER); err != nil {
		s.denyAs(s.hooks.ClientEnrollment, now, audit.ActorOperator, operator.ID)
		return Token{}, ErrDenied
	}
	s.prune(now)
	if len(s.pending) >= maxPending {
		s.denyAs(s.hooks.ClientEnrollment, now, audit.ActorOperator, operator.ID)
		return Token{}, ErrUnavailable
	}
	var tok Token
	if _, err := rand.Read(tok.b[:]); err != nil || tok.b == ([32]byte{}) {
		return Token{}, ErrUnavailable
	}
	key := sha256.Sum256(tok.b[:])
	if _, dup := s.pending[key]; dup {
		return Token{}, ErrUnavailable
	}
	if err := s.record(s.hooks.ClientEnrollment, now, audit.ActorOperator, operator.ID, audit.OutcomeAllowed); err != nil {
		return Token{}, ErrUnavailable
	}
	s.pending[key] = pending{binding: binding, role: role, csrHash: sha256.Sum256(csrDER), expires: now.Add(pendingTTL)}
	return tok, nil
}

// Enroll redeems token for the exact approved peer and CSR and issues a
// credential under a new random ID. peer MUST be the current verified WhoIs
// of the transport connection. A token is usable strictly before its
// deadline; at or after it the token is consumed and ErrExpired returned.
func (s *Service) Enroll(ctx context.Context, peer TailnetPeer, token Token, csrDER []byte) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.ready(ctx) {
		return Credential{}, ErrUnavailable
	}
	key := sha256.Sum256(token.b[:])
	p, ok := s.pending[key]
	if token.b == ([32]byte{}) || !ok {
		s.prune(now)
		s.deny(s.hooks.ClientEnrollment, now)
		return Credential{}, ErrDenied
	}
	if !now.Before(p.expires) {
		s.prune(now) // removes key and every other stale approval
		s.deny(s.hooks.ClientEnrollment, now)
		return Credential{}, ErrExpired
	}
	s.prune(now)
	// parseCSR bounds csrDER before it is hashed and verifies proof of
	// possession of the CSR key.
	csr, err := parseCSR(csrDER)
	if err != nil {
		s.deny(s.hooks.ClientEnrollment, now)
		return Credential{}, ErrDenied
	}
	h := sha256.Sum256(csrDER)
	if !peerMatches(peer, p.binding) || subtle.ConstantTimeCompare(h[:], p.csrHash[:]) != 1 {
		s.deny(s.hooks.ClientEnrollment, now)
		return Credential{}, ErrDenied
	}
	if len(s.records) >= maxRegistryEntries {
		s.deny(s.hooks.ClientEnrollment, now)
		return Credential{}, ErrUnavailable
	}
	id, err := s.newID()
	if err != nil {
		return Credential{}, ErrUnavailable
	}
	der, err := s.authority.issue(ctx, id, csr, now)
	if err != nil {
		s.deny(s.hooks.ClientEnrollment, now)
		return Credential{}, ErrUnavailable
	}
	// Signing may block; recheck the request and approval before granting.
	if !s.ready(ctx) {
		return Credential{}, ErrUnavailable
	}
	if now = s.now(); !now.Before(p.expires) {
		delete(s.pending, key)
		s.deny(s.hooks.ClientEnrollment, now)
		return Credential{}, ErrExpired
	}
	rec := record{ID: id, Role: p.role, Binding: p.binding, Fingerprint: sha256.Sum256(der)}
	if !validRecord(rec) {
		return Credential{}, ErrUnavailable
	}
	corr, err := randomID()
	if err != nil {
		return Credential{}, ErrUnavailable
	}
	if err := s.recordCorr(s.hooks.ClientEnrollment, now, audit.ActorClient, id, corr, audit.OutcomeAllowed); err != nil {
		return Credential{}, ErrUnavailable
	}
	s.records[id] = rec
	if err := s.disk.save(s.records); err != nil {
		delete(s.records, id)
		s.fail(s.hooks.ClientEnrollment, now, audit.ActorClient, id, corr)
		return Credential{}, ErrUnavailable
	}
	delete(s.pending, key)
	return Credential{ID: id, CertificateDER: der, RootDER: s.authority.rootDER()}, nil
}

// Renew replaces the current certificate of an enrolled peer with one for a
// distinct key, keeping ID, role and binding. peer MUST be the current
// verified WhoIs and currentDER the leaf from the authenticated mTLS
// handshake (proof of possession), never request bytes.
func (s *Service) Renew(ctx context.Context, peer TailnetPeer, currentDER, csrDER []byte) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.ready(ctx) {
		return Credential{}, ErrUnavailable
	}
	old, cert, err := s.current(peer, currentDER, now)
	if err != nil {
		s.deny(s.hooks.ClientEnrollment, now)
		return Credential{}, err
	}
	csr, err := parseCSR(csrDER)
	if err != nil || bytes.Equal(csr.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
		s.denyAs(s.hooks.ClientEnrollment, now, audit.ActorClient, old.ID)
		return Credential{}, ErrDenied
	}
	der, err := s.authority.issue(ctx, old.ID, csr, now)
	if err != nil {
		s.denyAs(s.hooks.ClientEnrollment, now, audit.ActorClient, old.ID)
		return Credential{}, ErrUnavailable
	}
	// Signing may block; recheck the request and current certificate.
	if !s.ready(ctx) {
		return Credential{}, ErrUnavailable
	}
	now = s.now()
	if _, _, err := s.current(peer, currentDER, now); err != nil {
		s.denyAs(s.hooks.ClientEnrollment, now, audit.ActorClient, old.ID)
		return Credential{}, err
	}
	corr, err := randomID()
	if err != nil {
		return Credential{}, ErrUnavailable
	}
	if err := s.recordCorr(s.hooks.ClientEnrollment, now, audit.ActorClient, old.ID, corr, audit.OutcomeAllowed); err != nil {
		return Credential{}, ErrUnavailable
	}
	next := old
	next.Fingerprint = sha256.Sum256(der)
	s.records[old.ID] = next
	if err := s.disk.save(s.records); err != nil {
		s.records[old.ID] = old
		s.fail(s.hooks.ClientEnrollment, now, audit.ActorClient, old.ID, corr)
		return Credential{}, ErrUnavailable
	}
	return Credential{ID: old.ID, CertificateDER: der, RootDER: s.authority.rootDER()}, nil
}

// Revoke deletes the active record for id. Only a verified local operator may
// revoke. If the allowed audit record cannot be written the revocation is not
// performed and an error is returned (never success); the client keeps its
// current rights until a revocation is both audited and durably saved.
func (s *Service) Revoke(ctx context.Context, operator LocalPeer, id ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.ready(ctx) {
		return ErrUnavailable
	}
	if !verifiedOperator(operator) {
		s.deny(s.hooks.ClientEnrollment, now)
		return ErrDenied
	}
	old, ok := s.records[id]
	if !ok {
		s.denyAs(s.hooks.ClientEnrollment, now, audit.ActorOperator, operator.ID)
		return ErrDenied
	}
	corr, err := randomID()
	if err != nil {
		return ErrUnavailable
	}
	if err := s.recordCorr(s.hooks.ClientEnrollment, now, audit.ActorOperator, operator.ID, corr, audit.OutcomeAllowed); err != nil {
		return ErrUnavailable
	}
	delete(s.records, id)
	if err := s.disk.save(s.records); err != nil {
		s.records[id] = old
		s.fail(s.hooks.ClientEnrollment, now, audit.ActorOperator, operator.ID, corr)
		return ErrUnavailable
	}
	return nil
}

// AuthorizeRemote verifies certDER against the authority and the registry on
// every call and returns the caller ID when action is permitted. Remote
// callers can never be granted ActionAdmin.
//
// peer MUST be the current verified WhoIs of the transport connection and
// certDER MUST be the leaf certificate from the authenticated mTLS handshake
// (proof of possession of its key), never bytes taken from the request.
// A correctly signed but expired certificate returns ErrExpired and is never
// granted.
func (s *Service) AuthorizeRemote(ctx context.Context, peer TailnetPeer, certDER []byte, action Action, target ID) (ID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.ready(ctx) {
		return ID{}, ErrUnavailable
	}
	rec, _, err := s.current(peer, certDER, now)
	if err != nil {
		s.deny(s.hooks.APIAuth, now)
		return ID{}, err
	}
	switch {
	case action == ActionRead && rec.Role == RoleRead && target.IsZero():
	case action == ActionIngest && rec.Role == RoleIngest && target == rec.ID:
	default:
		s.denyAs(s.hooks.APIAuth, now, audit.ActorClient, rec.ID)
		return ID{}, ErrDenied
	}
	if err := s.record(s.hooks.APIAuth, now, audit.ActorClient, rec.ID, audit.OutcomeAllowed); err != nil {
		return ID{}, ErrDenied
	}
	return rec.ID, nil
}

// AuthorizeLocal permits ActionAdmin to a verified local operator only.
func (s *Service) AuthorizeLocal(ctx context.Context, operator LocalPeer, action Action) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.ready(ctx) {
		return ErrUnavailable
	}
	if !verifiedOperator(operator) {
		s.deny(s.hooks.APIAuth, now)
		return ErrDenied
	}
	if action != ActionAdmin {
		s.denyAs(s.hooks.APIAuth, now, audit.ActorOperator, operator.ID)
		return ErrDenied
	}
	if err := s.record(s.hooks.APIAuth, now, audit.ActorOperator, operator.ID, audit.OutcomeAllowed); err != nil {
		return ErrDenied
	}
	return nil
}

// current verifies der through the authority and matches it to its active,
// unrevoked record bound to peer. The service cannot itself prove possession:
// der MUST be the leaf presented in the authenticated mTLS handshake, never
// request bytes. A correctly signed but expired leaf yields ErrExpired;
// anything else ErrDenied.
func (s *Service) current(peer TailnetPeer, der []byte, now time.Time) (record, *x509.Certificate, error) {
	cert, err := s.authority.verify(der, now)
	if err != nil {
		if errors.Is(err, ErrExpired) {
			return record{}, nil, ErrExpired
		}
		return record{}, nil, ErrDenied
	}
	id, err := certificateID(cert)
	if err != nil {
		return record{}, nil, ErrDenied
	}
	rec, ok := s.records[id]
	if !ok {
		return record{}, nil, ErrDenied
	}
	fp := sha256.Sum256(cert.Raw)
	if subtle.ConstantTimeCompare(fp[:], rec.Fingerprint[:]) != 1 || !peerMatches(peer, rec.Binding) {
		return record{}, nil, ErrDenied
	}
	return rec, cert, nil
}

func (s *Service) ready(ctx context.Context) bool {
	return ctx != nil && ctx.Err() == nil && !s.closed && !s.unusable
}

// prune drops every pending approval whose deadline has been reached.
func (s *Service) prune(now time.Time) {
	for k, p := range s.pending {
		if !now.Before(p.expires) {
			delete(s.pending, k)
		}
	}
}

func (s *Service) newID() (ID, error) {
	for range 8 {
		id, err := randomID()
		if err != nil {
			return ID{}, err
		}
		if _, used := s.records[id]; !used {
			return id, nil
		}
	}
	return ID{}, ErrUnavailable
}

type hook func(audit.Meta, audit.Outcome) error

func (s *Service) record(h hook, now time.Time, kind audit.ActorKind, actor ID, o audit.Outcome) error {
	corr, err := randomID()
	if err != nil {
		return err
	}
	return s.recordCorr(h, now, kind, actor, corr, o)
}

func (s *Service) recordCorr(h hook, now time.Time, kind audit.ActorKind, actor, corr ID, o audit.Outcome) error {
	return h(audit.Meta{At: now, ActorKind: kind, ActorID: actor, CorrelationID: corr}, o)
}

// deny records a best-effort denial by an unknown, unverified caller.
func (s *Service) deny(h hook, now time.Time) {
	if actor, err := randomID(); err == nil {
		_ = s.record(h, now, audit.ActorUnknown, actor, audit.OutcomeDenied)
	}
}

// denyAs records a best-effort denial by an already verified caller of kind.
func (s *Service) denyAs(h hook, now time.Time, kind audit.ActorKind, actor ID) {
	_ = s.record(h, now, kind, actor, audit.OutcomeDenied)
}

// fail marks the instance unusable after an ambiguous save and records an
// error correlated with the allowed event under the same actor kind.
func (s *Service) fail(h hook, now time.Time, kind audit.ActorKind, actor, corr ID) {
	s.unusable = true
	_ = s.recordCorr(h, now, kind, actor, corr, audit.OutcomeError)
}

func randomID() (ID, error) {
	var id ID
	if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
		return ID{}, ErrUnavailable
	}
	return id, nil
}

func verifiedOperator(p LocalPeer) bool { return p.Operator && !p.ID.IsZero() }

func roleTag(r Role) (string, bool) {
	switch r {
	case RoleRead:
		return tagClient, true
	case RoleIngest:
		return tagAgent, true
	}
	return "", false
}

func validIdentifier(s string, optional bool) bool {
	if s == "" {
		return optional
	}
	if len(s) > maxIdentifier {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// validBinding requires a bounded printable node, an optional user (empty is
// allowed only because every binding is to a tagged node) and the exact tag
// of role.
func validBinding(b Binding, r Role) bool {
	tag, ok := roleTag(r)
	return ok && b.Tag == tag && validIdentifier(b.NodeID, false) && validIdentifier(b.UserID, true)
}

func validRecord(r record) bool {
	return !r.ID.IsZero() && r.Fingerprint != ([32]byte{}) && validBinding(r.Binding, r.Role)
}

// peerMatches compares the current WhoIs identity exactly with b.
func peerMatches(p TailnetPeer, b Binding) bool {
	if p.NodeID != b.NodeID || p.UserID != b.UserID {
		return false
	}
	for _, t := range p.Tags {
		if t == b.Tag {
			return true
		}
	}
	return false
}
