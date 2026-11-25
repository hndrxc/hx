package domain

import "time"

// DataStatus reports availability independently of freshness and health.
// Zero is explicit unknown.
type DataStatus uint8

const (
	DataStatusUnknown DataStatus = iota
	DataStatusAvailable
	DataStatusUnavailable
	DataStatusUnsupported
	DataStatusPermissionDenied
)

// Health is the last validated health signal reported by the source. Zero is
// explicit unknown.
type Health uint8

const (
	HealthUnknown Health = iota
	HealthHealthy
	HealthDegraded
	HealthUnhealthy
)

// Freshness records whether the observed data is current. Zero is explicit
// unknown.
type Freshness uint8

const (
	FreshnessUnknown Freshness = iota
	FreshnessFresh
	FreshnessStale
)

// State is the observed condition of a resource. DataStatus preserves the
// collection status, while Health keeps the last validated health separately,
// so a failing collection never erases the most recent genuine signal.
type State struct {
	DataStatus DataStatus
	Health     Health
	Freshness  Freshness
	ObservedAt time.Time
}

// EffectiveHealth returns the observed health only for available, fresh data
// with an observation time. A missing or unknown signal is not unhealthy.
func (s State) EffectiveHealth() Health {
	if s.DataStatus != DataStatusAvailable || s.Freshness != FreshnessFresh ||
		s.ObservedAt.IsZero() || s.Health > HealthUnhealthy {
		return HealthUnknown
	}
	return s.Health
}

// Resource is one independently addressable thing observed by one integration
// within one scope. A non-nil TombstonedAt marks a terminal record that
// replaces the active snapshot; the ID is stable and a later explicit sighting
// revives it with a fresh snapshot.
type Resource struct {
	ID           ResourceID
	Kind         Kind
	Source       Source
	DisplayName  string
	State        State
	TombstonedAt *time.Time
}
