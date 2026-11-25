package domain

import (
	"testing"
	"time"
)

func TestRelationshipValid(t *testing.T) {
	at := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	src := Source{IntegrationID: "acct-01", Scope: "us-east-1"}
	from, err := NewResourceID(src, KindHost, "host-a")
	if err != nil {
		t.Fatal(err)
	}
	to, err := NewResourceID(src, KindDevice, "device-b")
	if err != nil {
		t.Fatal(err)
	}
	ev := Evidence{Source: src, Reference: "ref-1", ObservedAt: at}

	cases := []struct {
		name string
		r    Relationship
		want bool
	}{
		{"valid hosts", Relationship{FromResourceID: from, ToResourceID: to, Kind: RelationshipKindHosts, Evidence: []Evidence{ev}}, true},
		{"default", Relationship{}, false},
		{"missing from", Relationship{ToResourceID: to, Kind: RelationshipKindHosts, Evidence: []Evidence{ev}}, false},
		{"missing to", Relationship{FromResourceID: from, Kind: RelationshipKindHosts, Evidence: []Evidence{ev}}, false},
		{"unspecified kind", Relationship{FromResourceID: from, ToResourceID: to, Evidence: []Evidence{ev}}, false},
		{"no evidence", Relationship{FromResourceID: from, ToResourceID: to, Kind: RelationshipKindHosts}, false},
		{"unattributed evidence", Relationship{FromResourceID: from, ToResourceID: to, Kind: RelationshipKindHosts, Evidence: []Evidence{ev, {Reference: "unattributed", ObservedAt: at}}}, false},
	}
	for _, tc := range cases {
		if got := tc.r.Valid(); got != tc.want {
			t.Errorf("%s: Valid() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
