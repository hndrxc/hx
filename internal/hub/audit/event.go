// Package audit implements the hub's tamper-evident audit chain.
//
// Wire format v1 is JSONL: one compact JSON object per record, terminated by
// a single LF. Each record carries the previous record's hash, and its own
// hash is the lowercase hex SHA-256 of the same compact object without the
// trailing "hash" member (LF excluded).
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

const (
	wireVersion = 1
	// maxFrame bounds a whole frame, LF included.
	maxFrame = 1024

	zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

// ID is an opaque 16-byte identifier. Callers derive stable IDs from
// verified metadata, never from raw inputs.
type ID [16]byte

// IsZero reports whether the ID is the all-zero value.
func (id ID) IsZero() bool { return id == ID{} }

func (id ID) String() string { return hex.EncodeToString(id[:]) }

// ActorKind classifies the actor of an event.
type ActorKind string

const (
	ActorOperator    ActorKind = "operator"
	ActorClient      ActorKind = "client"
	ActorIntegration ActorKind = "integration"
	// ActorUnknown marks unattributed denials/errors; ActorID must then be a
	// trusted opaque per-attempt ID.
	ActorUnknown ActorKind = "unknown"
)

// Action is the audited privileged operation.
type Action string

const (
	ActionVaultUnseal         Action = "vault_unseal"
	ActionSecretAccess        Action = "secret_access"
	ActionAPIAuth             Action = "api_auth"
	ActionClientEnrollment    Action = "client_enrollment"
	ActionClientConnection    Action = "client_connection"
	ActionTLSTrustApproval    Action = "tls_trust_approval"
	ActionTLSTrustRotation    Action = "tls_trust_rotation"
	ActionTLSTrustReplacement Action = "tls_trust_replacement"
	ActionTLSPinMismatch      Action = "tls_pin_mismatch"
)

// Outcome is the result of the audited operation.
type Outcome string

const (
	OutcomeAllowed Outcome = "allowed"
	OutcomeDenied  Outcome = "denied"
	OutcomeError   Outcome = "error"
)

// Event is one audited decision.
type Event struct {
	At            time.Time
	ActorKind     ActorKind
	ActorID       ID
	IntegrationID ID // zero means not applicable
	Action        Action
	Outcome       Outcome
	CorrelationID ID
}

// Checkpoint identifies a chain position.
type Checkpoint struct {
	Sequence uint64 `json:"sequence"`
	Hash     string `json:"hash"`
}

// Genesis returns the checkpoint preceding the first record.
func Genesis() Checkpoint { return Checkpoint{Sequence: 0, Hash: zeroHash} }

var (
	// ErrInvalidEvent reports an event that may not be recorded.
	ErrInvalidEvent = errors.New("audit: invalid event")
	// ErrHooksUnconfigured is returned by nil or zero Hooks.
	ErrHooksUnconfigured = errors.New("audit: hooks not configured")
)

// validate checks event invariants shared by writing and verification.
func (e Event) validate() error {
	if e.At.IsZero() || e.At.UTC().Year() < 1 || e.At.UTC().Year() > 9999 {
		return ErrInvalidEvent
	}
	switch e.ActorKind {
	case ActorOperator, ActorClient, ActorIntegration, ActorUnknown:
	default:
		return ErrInvalidEvent
	}
	switch e.Action {
	case ActionVaultUnseal, ActionSecretAccess, ActionAPIAuth, ActionClientEnrollment, ActionClientConnection,
		ActionTLSTrustApproval, ActionTLSTrustRotation, ActionTLSTrustReplacement, ActionTLSPinMismatch:
	default:
		return ErrInvalidEvent
	}
	switch e.Outcome {
	case OutcomeAllowed, OutcomeDenied, OutcomeError:
	default:
		return ErrInvalidEvent
	}
	if e.ActorID.IsZero() || e.CorrelationID.IsZero() {
		return ErrInvalidEvent
	}
	if e.ActorKind == ActorUnknown && e.Outcome == OutcomeAllowed {
		return ErrInvalidEvent
	}
	if e.Action == ActionSecretAccess && e.IntegrationID.IsZero() {
		return ErrInvalidEvent
	}
	return nil
}

// body is the hashed portion of a frame; field order is the wire order.
type body struct {
	Version       int    `json:"version"`
	Sequence      uint64 `json:"sequence"`
	Previous      string `json:"previous"`
	Time          string `json:"time"`
	ActorKind     string `json:"actor_kind"`
	ActorID       string `json:"actor_id"`
	IntegrationID string `json:"integration_id"`
	Action        string `json:"action"`
	Outcome       string `json:"outcome"`
	CorrelationID string `json:"correlation_id"`
}

// encode returns the complete frame (LF included) for event following prev,
// and the checkpoint after it.
func encode(event Event, prev Checkpoint) ([]byte, Checkpoint, error) {
	if err := event.validate(); err != nil {
		return nil, Checkpoint{}, err
	}
	if !validHash(prev.Hash) || prev.Sequence == ^uint64(0) {
		return nil, Checkpoint{}, errors.New("audit: invalid previous checkpoint")
	}
	b := body{
		Version:       wireVersion,
		Sequence:      prev.Sequence + 1,
		Previous:      prev.Hash,
		Time:          event.At.UTC().Format(time.RFC3339Nano),
		ActorKind:     string(event.ActorKind),
		ActorID:       event.ActorID.String(),
		IntegrationID: event.IntegrationID.String(),
		Action:        string(event.Action),
		Outcome:       string(event.Outcome),
		CorrelationID: event.CorrelationID.String(),
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, Checkpoint{}, err
	}
	sum := sha256.Sum256(raw)
	h := hex.EncodeToString(sum[:])
	frame := make([]byte, 0, len(raw)+len(`,"hash":""}`)+len(h)+1)
	frame = append(frame, raw[:len(raw)-1]...)
	frame = append(frame, `,"hash":"`...)
	frame = append(frame, h...)
	frame = append(frame, '"', '}', '\n')
	if len(frame) > maxFrame {
		return nil, Checkpoint{}, errors.New("audit: frame too large")
	}
	return frame, Checkpoint{Sequence: b.Sequence, Hash: h}, nil
}

func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Meta is the verified metadata common to every audited hook.
type Meta struct {
	At            time.Time
	ActorKind     ActorKind
	ActorID       ID
	IntegrationID ID // zero means not applicable; required for SecretAccess
	CorrelationID ID
}

type appender interface {
	Append(Event) (Checkpoint, error)
}

// Hooks are typed entry points for recording privileged decisions. Callers
// record the audit event first and grant only when the hook returns nil; a
// denial remains a denial when the hook fails. The zero value and a nil
// *Hooks fail closed.
type Hooks struct {
	log appender
}

// NewHooks builds Hooks over log, typically a *Log. A nil log yields Hooks
// that fail closed.
func NewHooks(log interface {
	Append(Event) (Checkpoint, error)
}) Hooks {
	if log == nil {
		return Hooks{}
	}
	if v := reflect.ValueOf(log); v.Kind() == reflect.Pointer && v.IsNil() {
		return Hooks{}
	}
	return Hooks{log: log}
}

func (h *Hooks) record(a Action, m Meta, o Outcome) error {
	if h == nil || h.log == nil {
		return ErrHooksUnconfigured
	}
	ev := Event{
		At:            m.At,
		ActorKind:     m.ActorKind,
		ActorID:       m.ActorID,
		IntegrationID: m.IntegrationID,
		Action:        a,
		Outcome:       o,
		CorrelationID: m.CorrelationID,
	}
	if err := ev.validate(); err != nil {
		return err
	}
	_, err := h.log.Append(ev)
	return err
}

// VaultUnseal records a vault unseal decision.
func (h *Hooks) VaultUnseal(m Meta, o Outcome) error { return h.record(ActionVaultUnseal, m, o) }

// SecretAccess records a secret access decision; IntegrationID is required.
func (h *Hooks) SecretAccess(m Meta, o Outcome) error { return h.record(ActionSecretAccess, m, o) }

// APIAuth records an API authentication decision.
func (h *Hooks) APIAuth(m Meta, o Outcome) error { return h.record(ActionAPIAuth, m, o) }

// ClientEnrollment records a client enrollment decision.
func (h *Hooks) ClientEnrollment(m Meta, o Outcome) error {
	return h.record(ActionClientEnrollment, m, o)
}

// ClientConnection records a client connection decision.
func (h *Hooks) ClientConnection(m Meta, o Outcome) error {
	return h.record(ActionClientConnection, m, o)
}

// TLSTrustApproval records a TLS trust approval decision.
func (h *Hooks) TLSTrustApproval(m Meta, o Outcome) error {
	return h.record(ActionTLSTrustApproval, m, o)
}

// TLSTrustRotation records a TLS trust rotation decision.
func (h *Hooks) TLSTrustRotation(m Meta, o Outcome) error {
	return h.record(ActionTLSTrustRotation, m, o)
}

// TLSTrustReplacement records a TLS trust replacement (promotion) decision.
func (h *Hooks) TLSTrustReplacement(m Meta, o Outcome) error {
	return h.record(ActionTLSTrustReplacement, m, o)
}

// TLSPinMismatch records a TLS pin mismatch; IntegrationID is the actor.
func (h *Hooks) TLSPinMismatch(m Meta, o Outcome) error {
	return h.record(ActionTLSPinMismatch, m, o)
}
