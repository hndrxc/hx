package domain

import "time"

// Outcome is the result of one source attempt. Zero is explicit unknown.
type Outcome uint8

const (
	OutcomeUnknown Outcome = iota
	OutcomeComplete
	OutcomePartial
	OutcomeUnavailable
	OutcomeUnsupported
	OutcomePermissionDenied
)

// SourceStatus tracks the latest attempt of a source over one scope.
// Times identify when attempts started. LastSuccessAt holds the timestamp of
// the most recent COMPLETE attempt, even after partial or failed attempts.
type SourceStatus struct {
	Source        Source
	Outcome       Outcome
	LastAttemptAt time.Time
	LastSuccessAt time.Time
}

// Authoritative reports whether a candidate can infer absence for its own
// source and scope. Compare attempt start times so a late complete result
// cannot remove records after a newer partial or failed result. For the first
// result, supply a prior status with the same Source and zero timestamps.
func Authoritative(candidate, prior SourceStatus) bool {
	return candidate.Outcome == OutcomeComplete &&
		candidate.Source.IntegrationID != "" && candidate.Source.Scope != "" &&
		candidate.Source == prior.Source &&
		candidate.LastAttemptAt.After(prior.LastAttemptAt) &&
		candidate.LastAttemptAt.Equal(candidate.LastSuccessAt)
}
