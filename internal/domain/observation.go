package domain

import (
	"math"
	"time"
)

// Unit is the dimension of an observation value. Zero is explicit
// unspecified.
type Unit uint8

const (
	UnitUnspecified Unit = iota
	UnitCount
	UnitBytes
	UnitSeconds
	UnitRatio
	UnitCelsius
	UnitHertz
)

type numberKind uint8

const (
	numberUnset numberKind = iota
	numberInt64
	numberFloat64
)

// NumericValue holds one integer or double. Its zero value is unset.
type NumericValue struct {
	bits uint64
	kind numberKind
}

// Int64Value returns the integer variant holding v.
func Int64Value(v int64) NumericValue {
	return NumericValue{bits: uint64(v), kind: numberInt64}
}

// Float64Value returns the double variant holding v. Observation.Valid
// rejects NaN and infinities rather than converting them to missing values.
func Float64Value(v float64) NumericValue {
	return NumericValue{bits: math.Float64bits(v), kind: numberFloat64}
}

// Int64 returns the sample only if it is an integer, including zero.
func (n NumericValue) Int64() (int64, bool) {
	if n.kind != numberInt64 {
		return 0, false
	}
	return int64(n.bits), true
}

// Float64 returns the sample only if it is a double, including zero.
func (n NumericValue) Float64() (float64, bool) {
	if n.kind != numberFloat64 {
		return 0, false
	}
	return math.Float64frombits(n.bits), true
}

func (n NumericValue) valid() bool {
	if n.kind == numberInt64 {
		return true
	}
	f, ok := n.Float64()
	return ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

// Observation records the outcome of one metric measurement for a resource
// at ObservedAt, even when no sample could be obtained.
type Observation struct {
	ResourceID ResourceID
	Name       string
	State      DataStatus
	Unit       Unit
	Value      NumericValue
	ObservedAt time.Time
}

// Valid checks the time, metric key, and availability/value combination.
// A nonavailable result carries neither a numeric value nor a unit.
func (o Observation) Valid() bool {
	if o.ResourceID == "" || !isLowerSnakeCase(o.Name) || o.ObservedAt.IsZero() {
		return false
	}
	switch o.State {
	case DataStatusAvailable:
		return o.Unit >= UnitCount && o.Unit <= UnitHertz && o.Value.valid()
	case DataStatusUnknown, DataStatusUnavailable, DataStatusUnsupported, DataStatusPermissionDenied:
		return o.Unit == UnitUnspecified && o.Value.kind == numberUnset
	default:
		return false
	}
}

func isLowerSnakeCase(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '_' {
			if i+1 == len(s) || s[i+1] == '_' {
				return false
			}
		} else if !('a' <= c && c <= 'z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}
