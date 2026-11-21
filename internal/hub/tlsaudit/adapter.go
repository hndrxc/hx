// Package tlsaudit adapts TLS trust store audit callbacks to the hub audit
// chain. Only opaque verified IDs, the action, the outcome and the store's
// timestamp are recorded; origins, hostnames, certificates, fingerprints and
// raw errors never reach the log.
//
// An allowed event records prior authorization of a mutation, not that the
// transaction later succeeded.
package tlsaudit

import (
	"crypto/rand"
	"errors"

	"github.com/hndrxc/hx/internal/egress/tlstrust"
	"github.com/hndrxc/hx/internal/hub/audit"
)

// ErrInvalid reports a malformed adapter configuration or store event.
var ErrInvalid = errors.New("tlsaudit: invalid")

// New returns a store audit callback recording into hooks. operatorID
// attributes privileged trust mutations; integrationID attributes pin
// mismatches and is attached to every event. Both must be non-zero verified
// opaque IDs and hooks must be non-nil; hook failures are returned so the
// store fails closed.
func New(hooks *audit.Hooks, operatorID, integrationID audit.ID) (func(tlstrust.AuditEvent) error, error) {
	if hooks == nil || operatorID.IsZero() || integrationID.IsZero() {
		return nil, ErrInvalid
	}
	return func(ev tlstrust.AuditEvent) error {
		return record(hooks, operatorID, integrationID, ev)
	}, nil
}

func record(h *audit.Hooks, operatorID, integrationID audit.ID, ev tlstrust.AuditEvent) error {
	var call func(audit.Meta, audit.Outcome) error
	m := audit.Meta{At: ev.At, IntegrationID: integrationID}
	outcome := audit.OutcomeDenied
	if ev.Allowed {
		outcome = audit.OutcomeAllowed
	}
	switch ev.Action {
	case tlstrust.Approval:
		call = h.TLSTrustApproval
	case tlstrust.Rotation:
		call = h.TLSTrustRotation
	case tlstrust.Replacement:
		call = h.TLSTrustReplacement
	case tlstrust.PinMismatch:
		if ev.Allowed {
			return ErrInvalid
		}
		call = h.TLSPinMismatch
	default:
		return ErrInvalid
	}
	if ev.Action == tlstrust.PinMismatch {
		m.ActorKind, m.ActorID = audit.ActorIntegration, integrationID
	} else {
		m.ActorKind, m.ActorID = audit.ActorOperator, operatorID
	}
	corr, err := correlator()
	if err != nil {
		return err
	}
	m.CorrelationID = corr
	return call(m, outcome)
}

func correlator() (audit.ID, error) {
	var id audit.ID
	if _, err := rand.Read(id[:]); err != nil {
		return audit.ID{}, err
	}
	if id.IsZero() {
		return audit.ID{}, ErrInvalid
	}
	return id, nil
}
