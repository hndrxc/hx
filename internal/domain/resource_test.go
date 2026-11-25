package domain

import (
	"testing"
	"time"
)

func TestEffectiveHealth(t *testing.T) {
	at := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		state State
		want  Health
	}{
		{"available fresh healthy", State{DataStatus: DataStatusAvailable, Health: HealthHealthy, Freshness: FreshnessFresh, ObservedAt: at}, HealthHealthy},
		{"available fresh degraded", State{DataStatus: DataStatusAvailable, Health: HealthDegraded, Freshness: FreshnessFresh, ObservedAt: at}, HealthDegraded},
		{"available fresh unhealthy", State{DataStatus: DataStatusAvailable, Health: HealthUnhealthy, Freshness: FreshnessFresh, ObservedAt: at}, HealthUnhealthy},
		{"available fresh missing timestamp", State{DataStatus: DataStatusAvailable, Health: HealthHealthy, Freshness: FreshnessFresh}, HealthUnknown},
		{"available fresh unrecognized health", State{DataStatus: DataStatusAvailable, Health: Health(200), Freshness: FreshnessFresh, ObservedAt: at}, HealthUnknown},
		{"available fresh unknown health", State{DataStatus: DataStatusAvailable, Health: HealthUnknown, Freshness: FreshnessFresh, ObservedAt: at}, HealthUnknown},
		{"stale healthy becomes unknown", State{DataStatus: DataStatusAvailable, Health: HealthHealthy, Freshness: FreshnessStale, ObservedAt: at}, HealthUnknown},
		{"freshness unknown", State{DataStatus: DataStatusAvailable, Health: HealthHealthy, Freshness: FreshnessUnknown, ObservedAt: at}, HealthUnknown},
		{"unavailable", State{DataStatus: DataStatusUnavailable, Health: HealthHealthy, Freshness: FreshnessFresh, ObservedAt: at}, HealthUnknown},
		{"unsupported", State{DataStatus: DataStatusUnsupported, Health: HealthHealthy, Freshness: FreshnessFresh, ObservedAt: at}, HealthUnknown},
		{"permission denied", State{DataStatus: DataStatusPermissionDenied, Health: HealthHealthy, Freshness: FreshnessFresh, ObservedAt: at}, HealthUnknown},
		{"zero state", State{}, HealthUnknown},
	}
	for _, tc := range cases {
		if got := tc.state.EffectiveHealth(); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
