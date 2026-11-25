package domain

import "time"

// Event is a discrete, source-reported occurrence. ID is an opaque
// idempotency key chosen by the source; Kind is a stable lower_snake_case
// string; ResourceID links the event to a resource when one is involved.
type Event struct {
	ID         string
	Source     Source
	ResourceID *ResourceID
	Kind       string
	OccurredAt time.Time
	Summary    string
	Evidence   []Evidence
}
