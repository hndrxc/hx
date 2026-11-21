// Package client holds shared client-side view types.
package client

import (
	"errors"

	"github.com/hndrxc/hx/internal/sanitize"
)

// ErrSourceID is returned for any invalid source identifier. It never
// includes the rejected input.
var ErrSourceID = errors.New("client: invalid source id")

const maxSourceIDBytes = 128

// SourceID is an opaque, validated stable key. It is stored separately from
// any sanitized display text and is never derived from it.
type SourceID struct{ id string }

// String returns the exact validated ASCII identifier.
func (s SourceID) String() string { return s.id }

func newSourceID(raw string) (SourceID, error) {
	if len(raw) < 1 || len(raw) > maxSourceIDBytes {
		return SourceID{}, ErrSourceID
	}
	for i := range raw {
		c := raw[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if alnum {
			continue
		}
		if i > 0 && (c == '.' || c == '_' || c == ':' || c == '-') {
			continue
		}
		return SourceID{}, ErrSourceID
	}
	return SourceID{id: raw}, nil
}

// TextView is a plain-text view: a stable source ID, a sanitized label title
// and a sanitized log-style body. Content is inert text only.
type TextView struct {
	sourceID SourceID
	title    sanitize.Text
	body     sanitize.Text
}

// NewTextView validates sourceID and sanitizes title (as a label) and body
// (as a log).
func NewTextView(sourceID, title, body string) (TextView, error) {
	id, err := newSourceID(sourceID)
	if err != nil {
		return TextView{}, err
	}
	return TextView{sourceID: id, title: sanitize.Label(title), body: sanitize.Log(body)}, nil
}

// SourceID returns the stable identifier.
func (v TextView) SourceID() SourceID { return v.sourceID }

// Title returns the sanitized single-line title.
func (v TextView) Title() sanitize.Text { return v.title }

// Body returns the sanitized body.
func (v TextView) Body() sanitize.Text { return v.body }
