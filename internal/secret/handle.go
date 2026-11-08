package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
)

// IntegrationID identifies a third-party integration (e.g. "github", "cloudflare").
// Valid identifiers must be 1 to 64 bytes long, starting with 'a'-'z', followed by
// 'a'-'z', '0'-'9', '-', or '_'.
type IntegrationID string

// Scope identifies an authorized permission or capability within an integration (e.g. "token").
// Valid scopes must be 1 to 64 bytes long, starting with 'a'-'z', followed by
// 'a'-'z', '0'-'9', '-', or '_'.
type Scope string

// Source resolves plaintext for exactly one integration scope. The hub vault (S02) implements it.
// Open returns a caller-owned Value (the caller destroys it). Missing records return an error
// wrapping ErrNotFound; a locked vault returns one wrapping ErrLocked.
type Source interface {
	Open(ctx context.Context, integration IntegrationID, scope Scope) (*Value, error)
}

// Handle binds secret access to a single integration and an explicit list of authorized scopes.
// A Handle never exposes its underlying Source or key material.
type Handle struct {
	// src is stored as a pointer-to-interface (*Source) rather than a bare Source
	// interface or pointer-to-struct. When a Handle sits in an unexported struct field,
	// fmt reflection cannot invoke its Format/String methods. With *Source, reflection
	// formats the field as an opaque pointer address across all verbs (including invalid
	// verbs like %s/%q whose diagnostics dereference struct pointers, but leave pointer-to-interface
	// unexpanded).
	src         *Source
	integration IntegrationID
	scopes      []Scope // sorted, deduplicated
}

// validName reports whether s conforms to the identifier syntax:
// 1 to 64 bytes, starting with 'a'-'z', with subsequent bytes in 'a'-'z', '0'-'9', '-', or '_'.
func validName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	if s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// NewHandle validates and constructs a Handle bound to integration and scopes.
//
// NewHandle checks in order:
// 1. nil src returns ErrNoSource.
// 2. An invalid integration identifier returns ErrInvalidIntegration.
// 3. No scopes returns ErrNoScopes.
// 4. Any invalid scope returns ErrInvalidScope.
//
// Duplicate scopes are silently deduplicated, and the stored slice is sorted.
// The caller's input slice is not modified.
func NewHandle(src Source, integration IntegrationID, scopes ...Scope) (*Handle, error) {
	if src == nil {
		return nil, ErrNoSource
	}
	if !validName(string(integration)) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidIntegration, integration)
	}
	if len(scopes) == 0 {
		return nil, ErrNoScopes
	}

	scs := make([]Scope, len(scopes))
	for i, sc := range scopes {
		if !validName(string(sc)) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidScope, sc)
		}
		scs[i] = sc
	}
	slices.Sort(scs)
	deduped := slices.Compact(scs)

	srcCopy := src
	return &Handle{
		src:         &srcCopy,
		integration: integration,
		scopes:      deduped,
	}, nil
}

// Use resolves the secret for scope via the underlying Source, invokes fn with a direct view
// of the plaintext, and destroys the secret immediately upon return, error, or panic.
//
// If ctx is already cancelled, Use returns ctx.Err() without calling Source.Open.
// If scope is invalid, Use returns ErrInvalidScope.
// If scope is not declared on the Handle, Use returns ErrScopeNotDeclared without calling Source.Open.
//
// fn must not retain or modify the plaintext slice. Furthermore, fn must not call Destroy,
// Use, or Locked on the same Value (or any shared copy), because doing so may deadlock if
// a Destroy call is pending.
func (h *Handle) Use(ctx context.Context, scope Scope, fn func(plaintext []byte) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validName(string(scope)) {
		return fmt.Errorf("%w: %q", ErrInvalidScope, scope)
	}
	if h == nil || h.src == nil || *h.src == nil {
		return fmt.Errorf("%w: integration %q scope %q", ErrScopeNotDeclared, "", scope)
	}
	_, found := slices.BinarySearch(h.scopes, scope)
	if !found {
		return fmt.Errorf("%w: integration %q scope %q", ErrScopeNotDeclared, h.integration, scope)
	}

	v, err := (*h.src).Open(ctx, h.integration, scope)
	if err != nil {
		v.Destroy()
		return fmt.Errorf("secret: open %s/%s: %w", h.integration, scope, err)
	}
	if v == nil {
		return fmt.Errorf("secret: open %s/%s: %w", h.integration, scope, ErrNotFound)
	}

	defer v.Destroy()
	return v.Use(fn)
}

// Integration returns the bound integration identifier.
func (h Handle) Integration() IntegrationID {
	return h.integration
}

// Scopes returns a copy of the authorized scopes, in sorted order.
func (h Handle) Scopes() []Scope {
	return slices.Clone(h.scopes)
}

// String returns the safe redacted representation of the Handle:
// secret.Handle(<integration>: <scope1>,<scope2>).
func (h Handle) String() string {
	n := len("secret.Handle(: )") + len(h.integration)
	for i, s := range h.scopes {
		if i > 0 {
			n++
		}
		n += len(s)
	}

	var b strings.Builder
	b.Grow(n)
	b.WriteString("secret.Handle(")
	b.WriteString(string(h.integration))
	b.WriteString(": ")
	for i, s := range h.scopes {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(string(s))
	}
	b.WriteByte(')')
	return b.String()
}

// GoString returns the safe redacted representation of the Handle.
func (h Handle) GoString() string {
	return h.String()
}

// Format writes the safe redacted representation of the Handle for every formatting verb,
// ensuring underlying Source and key material are never emitted.
func (h Handle) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, h.String())
}

// MarshalJSON returns the JSON encoding containing only the integration identifier and scopes.
func (h Handle) MarshalJSON() ([]byte, error) {
	scopes := h.scopes
	if scopes == nil {
		scopes = []Scope{}
	}
	return json.Marshal(struct {
		Integration IntegrationID `json:"integration"`
		Scopes      []Scope       `json:"scopes"`
	}{
		Integration: h.integration,
		Scopes:      scopes,
	})
}

// LogValue returns a structured slog attribute group containing only integration and scopes.
func (h Handle) LogValue() slog.Value {
	scopes := make([]string, len(h.scopes))
	for i, s := range h.scopes {
		scopes[i] = string(s)
	}
	return slog.GroupValue(
		slog.String("integration", string(h.integration)),
		slog.Any("scopes", scopes),
	)
}
