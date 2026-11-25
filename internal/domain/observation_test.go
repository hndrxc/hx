package domain

import (
	"math"
	"testing"
	"time"
)

func TestObservationValidity(t *testing.T) {
	base := Observation{
		ResourceID: "r1_metric",
		Name:       "used_bytes",
		State:      DataStatusAvailable,
		ObservedAt: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
		Unit:       UnitBytes,
		Value:      Int64Value(0),
	}
	denied := base
	denied.State, denied.Unit, denied.Value = DataStatusPermissionDenied, UnitUnspecified, NumericValue{}

	cases := []struct {
		name string
		obs  Observation
		want bool
	}{
		{"available measured zero", base, true},
		{"denied with observation time", denied, true},
		{"zero observation", Observation{}, false},
		{"missing resource id", func() Observation { b := base; b.ResourceID = ""; return b }(), false},
		{"missing name", func() Observation { b := base; b.Name = ""; return b }(), false},
		{"non-lowercase name", func() Observation { b := base; b.Name = "Used_Bytes"; return b }(), false},
		{"available missing value", func() Observation { b := base; b.Value = NumericValue{}; return b }(), false},
		{"available missing timestamp", func() Observation { b := base; b.ObservedAt = time.Time{}; return b }(), false},
		{"available missing unit", func() Observation { b := base; b.Unit = UnitUnspecified; return b }(), false},
		{"unrecognized unit", func() Observation { b := base; b.Unit = Unit(200); return b }(), false},
		{"NaN", func() Observation { b := base; b.Value = Float64Value(math.NaN()); return b }(), false},
		{"infinite", func() Observation { b := base; b.Value = Float64Value(math.Inf(-1)); return b }(), false},
		{"unavailable with value", func() Observation { b := base; b.State = DataStatusUnavailable; return b }(), false},
		{"denied with missing timestamp", func() Observation { b := denied; b.ObservedAt = time.Time{}; return b }(), false},
		{"unsupported without value", func() Observation { b := denied; b.State = DataStatusUnsupported; return b }(), true},
		{"unknown without value", func() Observation { b := denied; b.State = DataStatusUnknown; return b }(), true},
		{"unrecognized state", func() Observation { b := denied; b.State = DataStatus(200); return b }(), false},
	}
	for _, tc := range cases {
		if got := tc.obs.Valid(); got != tc.want {
			t.Errorf("%s: Valid() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNumericValuePreservesPresenceAndPrecision(t *testing.T) {
	if _, present := (NumericValue{}).Int64(); present {
		t.Fatal("missing measurement reported as a measured integer")
	}
	for _, want := range []int64{0, math.MaxInt64, math.MinInt64} {
		if got, present := Int64Value(want).Int64(); !present || got != want {
			t.Errorf("measured %d returned (%d, %t)", want, got, present)
		}
	}
	if got, present := Float64Value(0.5).Float64(); !present || got != 0.5 {
		t.Errorf("measured ratio returned (%v, %t)", got, present)
	}
}
