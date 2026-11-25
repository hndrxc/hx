package domain

import (
	"testing"
	"time"
)

func TestAuthoritative(t *testing.T) {
	at := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	later := at.Add(time.Minute)

	aws := Source{IntegrationID: "acct-01", Scope: "us-east-1"}
	gcp := Source{IntegrationID: "acct-02", Scope: "us-east-1"}

	cases := []struct {
		name      string
		candidate SourceStatus
		prior     SourceStatus
		want      bool
	}{
		{"complete newer exact source", SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: later, LastSuccessAt: later},
			SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: at, LastSuccessAt: at}, true},
		{"complete first success allowed", SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: later, LastSuccessAt: later},
			SourceStatus{Source: aws, Outcome: OutcomePartial, LastAttemptAt: at}, true},
		{"complete older denied", SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: at, LastSuccessAt: at},
			SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: later, LastSuccessAt: later}, false},
		{"complete same timestamp denied", SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: at, LastSuccessAt: at},
			SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: at, LastSuccessAt: at}, false},
		{"late complete after newer partial denied", SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: at, LastSuccessAt: at},
			SourceStatus{Source: aws, Outcome: OutcomePartial, LastAttemptAt: later}, false},
		{"complete with stale success timestamp denied", SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: later, LastSuccessAt: at},
			SourceStatus{Source: aws, Outcome: OutcomePartial, LastAttemptAt: at}, false},
		{"missing scope cannot remove", SourceStatus{Outcome: OutcomeComplete, LastAttemptAt: later, LastSuccessAt: later}, SourceStatus{}, false},
		{"partial newer denied", SourceStatus{Source: aws, Outcome: OutcomePartial, LastAttemptAt: later},
			SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: at, LastSuccessAt: at}, false},
		{"unavailable newer denied", SourceStatus{Source: aws, Outcome: OutcomeUnavailable, LastAttemptAt: later},
			SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: at, LastSuccessAt: at}, false},
		{"unsupported newer denied", SourceStatus{Source: aws, Outcome: OutcomeUnsupported, LastAttemptAt: later},
			SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: at, LastSuccessAt: at}, false},
		{"permission denied newer denied", SourceStatus{Source: aws, Outcome: OutcomePermissionDenied, LastAttemptAt: later},
			SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: at, LastSuccessAt: at}, false},
		{"different integration denied", SourceStatus{Source: gcp, Outcome: OutcomeComplete, LastAttemptAt: later, LastSuccessAt: later},
			SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: at, LastSuccessAt: at}, false},
		{"different scope denied", SourceStatus{Source: Source{IntegrationID: "acct-01", Scope: "us-west-2"}, Outcome: OutcomeComplete, LastAttemptAt: later, LastSuccessAt: later},
			SourceStatus{Source: aws, Outcome: OutcomeComplete, LastAttemptAt: at, LastSuccessAt: at}, false},
	}
	for _, tc := range cases {
		if got := Authoritative(tc.candidate, tc.prior); got != tc.want {
			t.Errorf("%s: Authoritative() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
