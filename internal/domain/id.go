package domain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"unicode/utf8"
)

// resourceIDPrefix anchors the ID algorithm to version v1 of the resource
// schema.
const resourceIDPrefix = "hx.resource.v1\x00"

// resourceIDScheme is the printed scheme of a stable resource ID.
const resourceIDScheme = "r1_"

var (
	// ErrEmptyIntegrationID reports an empty source integration ID.
	ErrEmptyIntegrationID = errors.New("domain: empty integration id")
	// ErrEmptyScope reports an empty source scope.
	ErrEmptyScope = errors.New("domain: empty scope")
	// ErrEmptyNativeKey reports an empty provider native key.
	ErrEmptyNativeKey = errors.New("domain: empty native key")
	// ErrInvalidUTF8 reports an ID component that is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("domain: non-UTF-8 ID component")
	// ErrUnknownKind reports a kind that is not a usable kind token.
	ErrUnknownKind = errors.New("domain: unknown or unspecified kind")
	// ErrComponentTooLarge reports an ID component that cannot fit the uint32
	// big-endian length framing.
	ErrComponentTooLarge = errors.New("domain: ID component exceeds uint32 framing")
)

// maxComponentBytes bounds any single framed component. A longer component
// cannot be represented in a uint32 big-endian length field.
const maxComponentBytes = math.MaxUint32

// Source identifies one immutable integration instance (IntegrationID) and
// the stable reconciliation scope (Scope) it observes. It never carries
// hostnames, endpoints or secrets.
type Source struct {
	IntegrationID string
	Scope         string
}

// Kind is the canonical resource kind. Zero is the explicit unknown state.
type Kind uint8

const (
	KindUnknown Kind = iota
	KindService
	KindProject
	KindDeployment
	KindDNSRecord
	KindCertificate
	KindHost
	KindVirtualMachine
	KindStoragePool
	KindDevice
	KindBackup
)

// kindTokens maps each Kind to its canonical lower_snake_case token.
var kindTokens = [...]string{
	"unknown", "service", "project", "deployment", "dns_record",
	"certificate", "host", "virtual_machine", "storage_pool",
	"device", "backup",
}

// Token returns the canonical lower_snake_case token for k and whether k is
// a usable resource-kind token (known and not KindUnknown).
func (k Kind) Token() (string, bool) {
	if int(k) >= len(kindTokens) {
		return "", false
	}
	return kindTokens[k], k != KindUnknown
}

// ParseKind resolves a canonical token to its Kind. It reports whether the
// token is recognized; "unknown" resolves to KindUnknown.
func ParseKind(token string) (Kind, bool) {
	for i, t := range kindTokens {
		if t == token {
			return Kind(i), true
		}
	}
	return KindUnknown, false
}

// ResourceID is the stable identity of one resource. It never changes for
// the lifetime of the resource, is unique per integration ID + scope + kind +
// native key. A digest is not a way to conceal a secret.
type ResourceID string

// NewResourceID derives the stable ID for a resource observed by source with
// the given kind and provider native key.
//
// Each input is validated verbatim: IntegrationID, Scope and nativeKey must
// be non-empty valid UTF-8, and kind must be a known, non-unknown kind. Inputs
// are never trimmed, folded, or otherwise normalized, and the native key is
// treated as opaque and case-sensitive. Any component larger than the uint32
// framing limit is rejected before hashing.
func NewResourceID(source Source, kind Kind, nativeKey string) (ResourceID, error) {
	token, ok := kind.Token()
	if !ok {
		return "", ErrUnknownKind
	}
	if source.IntegrationID == "" {
		return "", ErrEmptyIntegrationID
	}
	if source.Scope == "" {
		return "", ErrEmptyScope
	}
	if nativeKey == "" {
		return "", ErrEmptyNativeKey
	}
	parts := [...]string{source.IntegrationID, source.Scope, token, nativeKey}
	for _, part := range parts {
		if uint64(len(part)) > maxComponentBytes {
			return "", ErrComponentTooLarge
		}
		if !utf8.ValidString(part) {
			return "", ErrInvalidUTF8
		}
	}

	h := sha256.New()
	h.Write([]byte(resourceIDPrefix))
	// The hash takes byte slices; use bounded scratch instead of converting
	// the entire native key to a new slice.
	var buf [256]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(buf[:4], uint32(len(part)))
		h.Write(buf[:4])
		for len(part) != 0 {
			n := copy(buf[:], part)
			h.Write(buf[:n])
			part = part[n:]
		}
	}
	var sum [sha256.Size]byte
	var id [len(resourceIDScheme) + 2*sha256.Size]byte
	copy(id[:], resourceIDScheme)
	hex.Encode(id[len(resourceIDScheme):], h.Sum(sum[:0]))
	return ResourceID(id[:]), nil
}
