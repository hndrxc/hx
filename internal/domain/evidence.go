package domain

import "time"

// Evidence ties a finding to the source that produced it. Reference is an
// opaque, non-secret locator chosen by the source (for example a log stream
// offset), never a credential or hostname.
type Evidence struct {
	Source     Source
	Reference  string
	ObservedAt time.Time
}
