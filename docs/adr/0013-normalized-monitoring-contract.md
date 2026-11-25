# ADR-0013: Normalized monitoring contract

- Status: Proposed
- Date: 2026-11-25
- Issue: https://github.com/hndrxc/hx/issues/22
- Supersedes: none

## Context

Collectors, the hub store, and read-only clients need a shared vocabulary. A failed poll or denied permission must not appear healthy or remove inventory. Provider-specific keys, credential material, and raw payloads must not become client fields.

## Decision

Use standard-library Go types in [`internal/domain`](../../internal/domain) and a versioned `hx.v1` Protobuf wire contract under [`proto/hx/v1`](../../proto/hx/v1). The generated Go messages and Connect bindings live under [`internal/api/v1`](../../internal/api/v1). The domain does not depend on transport. The wire service declares read-only methods only; it does not register a handler, start a listener, or add an ingest, admin, or provider passthrough method.

### Identity, time, and provenance

- A source is an immutable integration instance ID plus a stable reconciliation scope (the exact inventory a complete poll covers). These are non-secret tokens, not hostnames, URLs, account labels, or mutable display names. A scoped query filter requires the integration ID as well as the scope.
- A resource ID is `r1_` plus lowercase hex SHA-256. Hash `hx.resource.v1` followed by a NUL byte, then the integration ID, scope, canonical lower-snake-case kind token, and native key in that order. Each string is encoded as a four-byte big-endian byte length followed by its exact UTF-8 bytes. The native key is nonempty, case-sensitive, and immutable; names, timestamps and operational states never contribute to identity. The same native key in another kind, source or scope denotes a different resource. The digest is an identifier, not a secret-hiding mechanism; never use a credential as a key or publish the native key.
- Evidence identifies its source, a non-secret opaque evidence reference, and when it was observed. A relationship is a directed `(from, kind, to)` tuple backed by positive evidence. Evidence is not a raw payload, an arbitrary URL, or permission to fetch anything. Cross-source linking requires explicit evidence; the identity rule never merges inventory automatically.
- Times are UTC instants, encoded as Protobuf timestamps. `observed_at` describes the fact or sample, `occurred_at` the event, and `last_attempt_at` the collection attempt. Do not substitute poll time for an unknown provider event time. The wire format retains nanosecond precision; a missing timestamp is not the Unix epoch. Event identity is `(source, id)` so reprocessing the same event is idempotent. Metric identity is `(resource_id, name, observed_at)`; names are stable lower-snake-case keys, not labels.

### Health, availability, and reconciliation

| Dimension | Meaning |
|---|---|
| Data status | `available`, `unavailable`, `unsupported`, or `permission_denied`; unknown is the zero value. Non-available is not healthy and does not fabricate a metric. |
| Health | `healthy`, `degraded`, or `unhealthy`; unknown is the zero value. Effective health is unknown unless data is available, fresh, and has an observation time. A stale snapshot may retain its last known health. |
| Freshness | `fresh` or `stale`; unknown is the zero value. The scheduler and query implementation determine freshness from the last observation and the integration's policy. A failed poll never refreshes an old observation. |
| Source outcome | `complete`, `partial`, `unavailable`, `unsupported`, or `permission_denied`; unknown is the zero value. `last_attempt_at` is the attempt start time; `last_success_at` is the start time of the last complete attempt, not the last partial result. |

A numeric observation is either a signed 64-bit integer or a finite double with a known unit. Units are count, bytes, seconds, ratio (a fraction, not a percentage), degrees Celsius, and hertz. Every observation row records when the measurement outcome was observed, including a denied or unavailable outcome. Only an available row has a value and unit. An explicitly measured zero is valid; do not coerce an unknown unit or nonfinite sample into zero.

Only a newer `complete` poll for the exact source and scope may infer deletion from absence. Complete means the entire inventory was enumerated, including all provider pages, and reconciliation may happen only after the successful result is persisted. A partial poll may upsert positive findings. Partial, failed, or out-of-order results do not tombstone unmentioned resources or withdraw evidence by absence. Track the unit of reconciliation per source: completing one scope grants no authority over another. Preserve the last valid state and history separately from the latest attempt's outcome.

A tombstone is an explicit resource record with `tombstoned_at`; it ends the active snapshot, not the resource's identity or history. A later positive observation in a newer poll may revive that same ID. Resource queries hide tombstones by default and can opt in. Withdrawing one source's relationship evidence does not invalidate evidence from another source.

### Read queries and wire compatibility

The request messages document filters and total ordering for resources, metric history, events, relationships and source statuses. Unset filters do not restrict results; time bounds are inclusive at the start and exclusive at the end. A wildcard or unset filter never overrides authorization. An inaccessible or hidden resource is not returned by point lookups.

List requests use a continuation token with a default page size of 50 and a maximum of 200. Out-of-range sizes and invalid, expired, or mismatched tokens return `InvalidArgument`. Tokens are opaque and bound to the caller's authorized query, filters and sort order; a missing next token means the traversal is over. A server may cap a page below the requested count to obey its message-size limit. Order is deterministic for a stable result set; pages do not imply snapshot isolation across concurrent updates.

The package name, RPC paths and meanings of existing fields are stable within `v1`. Add fields with fresh field numbers and optional behavior. When removing a field or enum value, reserve both its name and number; never recycle them. Do not change a field's type, cardinality, JSON name or oneof membership in place. Older binary readers must tolerate unknown field numbers, and clients must treat unknown enum numbers as unknown rather than healthy. Binary Protobuf can preserve unknown fields on re-encoding; ProtoJSON does not provide that guarantee. Use a new version for incompatible changes and plan any migration with the storage and client owners.

## Consequences

[#23 (SQLite)](https://github.com/hndrxc/hx/issues/23) owns persistence, ordered reconciliation, retention, and migrations. [#24 (collector SDK)](https://github.com/hndrxc/hx/issues/24) owns source registration and declared kinds and metrics. [#28 (read queries)](https://github.com/hndrxc/hx/issues/28) owns authorized filtering, cursor implementation, and sanitized client views. This schema adds no runtime listener, provider permission, database state, or migration; reverting the schema and generated artifacts has no operational effect before downstream use. It does not replace the [live integration gate](../security/security-foundation.md).

## Verification

`CGO_ENABLED=0 go test ./internal/domain ./internal/api/... ./internal/architecture` checks identity, normalization, wire compatibility, and package dependency direction. The [cloud and homelab fixtures](../../internal/api/v1/testdata) use no real endpoints or secrets.

`go generate ./internal/api/v1` lints the schema and regenerates Protobuf and Connect bindings using the [pinned tools](../compatibility.md); CI checks generation for drift. For later changes, run the pinned Buf with `buf breaking --against /path/to/released/checkout` from the repository root. This is the initial schema, so there is no previous release to compare yet.

## References

- [Issue #22](https://github.com/hndrxc/hx/issues/22), [ADR-0004](0004-toolchain-and-dependency-selection.md), and [ADR-0011](0011-package-layout-and-dependency-direction.md) (checked 2026-11-25)
- [Protobuf language guide](https://protobuf.dev/programming-guides/proto3/) and [Buf breaking rules](https://buf.build/docs/breaking/rules/) (wire compatibility reference)
