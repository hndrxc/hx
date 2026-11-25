// Package domain defines the provider-neutral value types for the hx
// monitoring model: resources, observations, evidence, relationships, events
// and source status (D01, ADR-0011). It imports only the standard library,
// owns no adapters, and holds no state: it describes shapes and the small
// decisions derived from them.
//
// # Stable identifiers
//
// [ResourceID] is the stable identity of one resource observed by one
// integration instance within one reconciliation scope. It is derived
// deterministically from the integration ID, scope, kind and provider native
// key:
//
//	r1_ + hex(sha256("hx.resource.v1\x00" ||
//	     frame(integrationID) || frame(scope) ||
//	     frame(kind) || frame(nativeKey)))
//
// where frame(x) is the uint32 big-endian length of x followed by its UTF-8
// bytes. The native key is opaque and case-sensitive; it is never trimmed or
// case-folded, never published, and never merged across scopes.
//
// # Enums and time
//
// Kinds, data statuses, health, freshness, units, relationship kinds and
// outcomes are typed enums whose zero value is the explicit
// unknown/unspecified state. All timestamps are UTC.
//
// # Derived decisions
//
//   - [State.EffectiveHealth] resolves to unknown without an available,
//     fresh observation.
//   - [Observation.Valid] requires a timestamp for all metric rows and a
//     known unit and numeric value only for available samples.
//   - [Authoritative] gates reconciliation by absence on a newer COMPLETE
//     result for the exact same source and scope.
package domain
