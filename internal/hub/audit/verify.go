package audit

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	// ErrTornTail marks a bounded, non-LF-terminated suffix after every
	// complete record validated and the anchor (if any) matched.
	ErrTornTail = errors.New("audit: torn tail")
	// ErrCorrupt reports a complete record that is not the canonical frame
	// expected at its position. Record contents are never included.
	ErrCorrupt = errors.New("audit: corrupt record")
	// ErrOversized reports a record exceeding the frame bound.
	ErrOversized = errors.New("audit: oversized record")
	// ErrAnchorInvalid reports a malformed anchor checkpoint.
	ErrAnchorInvalid = errors.New("audit: invalid anchor")
	// ErrAnchorMissing reports that the chain ended before the anchor.
	ErrAnchorMissing = errors.New("audit: anchor not reached")
	// ErrAnchorMismatch reports a chain that disagrees with the anchor.
	ErrAnchorMismatch = errors.New("audit: anchor mismatch")
)

// wire mirrors a full frame for decoding.
type wire struct {
	body
	Hash string `json:"hash"`
}

func validAnchor(a Checkpoint) bool {
	if !validHash(a.Hash) {
		return false
	}
	return a.Sequence != 0 || a.Hash == zeroHash
}

// Verify checks the whole chain from genesis and returns its head. If anchor
// is non-nil the chain must contain exactly that checkpoint; the head may be
// beyond it. A torn tail is an error here (ErrTornTail).
func Verify(r io.Reader, anchor *Checkpoint) (Checkpoint, error) {
	head, _, err := scan(r, anchor)
	if err != nil {
		return Checkpoint{}, err
	}
	return head, nil
}

// scan streams r, validating each frame with a bounded buffer. On success
// validBytes is the length of the chain. On ErrTornTail, head and validBytes
// describe the valid prefix and are safe for recovery; for every other error
// recovery is not permitted.
func scan(r io.Reader, anchor *Checkpoint) (head Checkpoint, validBytes int64, err error) {
	if anchor != nil && !validAnchor(*anchor) {
		return Checkpoint{}, 0, ErrAnchorInvalid
	}
	head = Genesis()
	matched := anchor == nil || (anchor.Sequence == 0 && anchor.Hash == zeroHash)
	br := bufio.NewReaderSize(r, maxFrame)
	for {
		line, rerr := br.ReadSlice('\n')
		switch {
		case rerr == nil:
			// A frame longer than maxFrame surfaces as bufio.ErrBufferFull.
			next, verr := checkFrame(line, head)
			if verr != nil {
				return Checkpoint{}, 0, verr
			}
			head = next
			validBytes += int64(len(line))
			if anchor != nil && head.Sequence == anchor.Sequence {
				if head.Hash != anchor.Hash {
					return Checkpoint{}, 0, ErrAnchorMismatch
				}
				matched = true
			}
		case errors.Is(rerr, bufio.ErrBufferFull):
			return Checkpoint{}, 0, ErrOversized
		case rerr == io.EOF:
			if len(line) == 0 {
				if !matched {
					return Checkpoint{}, 0, fmt.Errorf("%w: head sequence %d", ErrAnchorMissing, head.Sequence)
				}
				return head, validBytes, nil
			}
			if len(line) >= maxFrame {
				return Checkpoint{}, 0, ErrOversized
			}
			if !matched {
				return Checkpoint{}, 0, fmt.Errorf("%w: head sequence %d", ErrAnchorMissing, head.Sequence)
			}
			return head, validBytes, ErrTornTail
		default:
			return Checkpoint{}, 0, fmt.Errorf("audit: read: %w", rerr)
		}
	}
}

// checkFrame validates one LF-terminated frame against prev by strictly
// decoding it and requiring the canonical re-encoding to match byte for
// byte. This rejects duplicate keys, reordering, whitespace, alternate time
// or hex forms, wrong versions, sequences, and hashes alike.
func checkFrame(line []byte, prev Checkpoint) (Checkpoint, error) {
	var w wire
	if err := json.Unmarshal(line, &w); err != nil {
		return Checkpoint{}, corruptFrame(prev)
	}
	ev, ok := w.event()
	if !ok {
		return Checkpoint{}, corruptFrame(prev)
	}
	want, next, err := encode(ev, prev)
	if err != nil || !bytes.Equal(want, line) {
		return Checkpoint{}, corruptFrame(prev)
	}
	return next, nil
}

func corruptFrame(prev Checkpoint) error {
	return fmt.Errorf("%w: expected sequence %d", ErrCorrupt, prev.Sequence+1)
}

func (w wire) event() (Event, bool) {
	var ev Event
	t, err := time.Parse(time.RFC3339Nano, w.Time)
	if err != nil {
		return ev, false
	}
	ev.At = t
	ev.ActorKind = ActorKind(w.ActorKind)
	ev.Action = Action(w.Action)
	ev.Outcome = Outcome(w.Outcome)
	for _, p := range []struct {
		s   string
		dst *ID
	}{{w.ActorID, &ev.ActorID}, {w.IntegrationID, &ev.IntegrationID}, {w.CorrelationID, &ev.CorrelationID}} {
		if len(p.s) != 32 {
			return ev, false
		}
		if _, err := hex.Decode(p.dst[:], []byte(p.s)); err != nil {
			return ev, false
		}
	}
	return ev, true
}
