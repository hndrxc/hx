package domain

// RelationshipKind classifies a relationship between two resources. Zero is
// explicit unspecified.
type RelationshipKind uint8

const (
	RelationshipKindUnspecified RelationshipKind = iota
	RelationshipKindHosts
	RelationshipKindDependsOn
	RelationshipKindBacksUp
	RelationshipKindMemberOf
)

// Relationship links FromResourceID to ToResourceID with evidence.
type Relationship struct {
	FromResourceID ResourceID
	ToResourceID   ResourceID
	Kind           RelationshipKind
	Evidence       []Evidence
}

// Valid checks that the edge has endpoints, a known kind and attributable
// evidence. It does not verify that the endpoint records exist.
func (r Relationship) Valid() bool {
	if r.FromResourceID == "" || r.ToResourceID == "" || len(r.Evidence) == 0 ||
		r.Kind <= RelationshipKindUnspecified || r.Kind > RelationshipKindMemberOf {
		return false
	}
	for _, e := range r.Evidence {
		if e.Source.IntegrationID == "" || e.Source.Scope == "" || e.Reference == "" || e.ObservedAt.IsZero() {
			return false
		}
	}
	return true
}
