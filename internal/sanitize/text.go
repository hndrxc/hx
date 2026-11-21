// Package sanitize provides defensive plain-text sanitization for log lines
// and labels. It strips terminal control sequences and Unicode controls,
// replaces malformed UTF-8, and enforces input/output byte caps while keeping
// the emitted text valid, rune-safe UTF-8.
package sanitize

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxInputBytes bounds how much input is scanned. Longer inputs are cut at
	// this prefix and reported as truncated.
	MaxInputBytes = 64 << 10
	// MaxLogBytes caps the byte length of a sanitized log line, including the
	// truncation marker when one is emitted.
	MaxLogBytes = 4 << 10
	// MaxLabelBytes caps the byte length of a sanitized label.
	MaxLabelBytes = 512
)

// Text is an opaque, already-sanitized string. It never retains raw input:
// String returns only the cleaned text.
type Text struct {
	s         string
	truncated bool
}

// String returns the sanitized text.
func (t Text) String() string { return t.s }

// Truncated reports whether the input byte cap or an output byte cap cut the
// text. Dropped control characters alone never count as truncation.
func (t Text) Truncated() bool { return t.truncated }

// Log sanitizes s for a log line. Line breaks (LF, CRLF, U+2028, U+2029)
// survive as LF; tabs become a space; all other controls are removed.
func Log(s string) Text {
	return sanitize(s, MaxLogBytes, '\n')
}

// Label sanitizes s for a single-line label. Line breaks (LF, CRLF, U+2028,
// U+2029) and tabs become a space; all other controls are removed.
func Label(s string) Text {
	return sanitize(s, MaxLabelBytes, ' ')
}

// emitter accumulates sanitized output. Until the first transformation it
// stays empty and the original bytes are passed through logically, so an
// unchanged input returns without any allocation or copy.
type emitter struct {
	s       string
	sb      *strings.Builder
	changed bool
	out     int
	maxOut  int
	cutAt   int
}

// beginAt materializes the clean prefix up to i when the first change is found.
func (e *emitter) beginAt(i int) {
	if !e.changed {
		if e.sb == nil {
			e.sb = new(strings.Builder)
		}
		e.sb.WriteString(e.s[:i])
		e.changed = true
	}
}

// drop records that the bytes from i forward are removed.
func (e *emitter) drop(i int) {
	e.beginAt(i)
}

// literal appends the rune s[i:i+size] verbatim. It reports false when the
// output cap is hit, recording the cut position.
func (e *emitter) literal(i, size int) bool {
	if e.out+size > e.maxOut {
		e.cutAt = i
		return false
	}
	if e.changed {
		e.sb.WriteString(e.s[i : i+size])
	}
	e.out += size
	return true
}

// mapped appends the single replacement byte rep for the rune at i.
func (e *emitter) mapped(i int, rep byte) bool {
	if e.out+1 > e.maxOut {
		e.cutAt = i
		return false
	}
	e.beginAt(i)
	e.sb.WriteByte(rep)
	e.out++
	return true
}

// replacement appends U+FFFD for one malformed byte at i.
func (e *emitter) replacement(i int) bool {
	if e.out+3 > e.maxOut {
		e.cutAt = i
		return false
	}
	e.beginAt(i)
	e.sb.WriteString("\uFFFD")
	e.out += 3
	return true
}

// sanitize implements the shared pipeline. lineRepl is the byte a line break
// becomes: '\n' for logs, ' ' for labels.
func sanitize(s string, maxOut int, lineRepl byte) Text {
	truncated := len(s) > MaxInputBytes
	if truncated {
		s = s[:MaxInputBytes]
	}
	e := emitter{s: s, maxOut: maxOut}

	i := 0
scan:
	for i < len(s) {
		b := s[i]
		if b < 0x80 {
			switch b {
			case '\t':
				if !e.mapped(i, ' ') {
					break scan
				}
				i++
			case '\n':
				if lineRepl == '\n' {
					// Logs keep LF verbatim; still a pass-through.
					if !e.literal(i, 1) {
						break scan
					}
				} else if !e.mapped(i, lineRepl) {
					break scan
				}
				i++
			case '\r':
				// Lone CR is dropped; a following LF is handled on its own.
				e.drop(i)
				i++
			case 0x1b:
				// 7-bit ESC introduces ANSI sequences; skipControl owns them.
				next, handled := skipControl(s, i)
				if handled {
					e.drop(i)
					i = next
				} else {
					e.drop(i)
					i++
				}
			default:
				if b < 0x20 || b == 0x7f {
					e.drop(i)
					i++
				} else if !e.literal(i, 1) {
					break scan
				} else {
					i++
				}
			}
			continue
		}

		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if b >= 0x80 && b <= 0x9f {
				// Raw C1 byte: a recognized control, handled by skipControl.
				next, handled := skipControl(s, i)
				if handled {
					e.drop(i)
					i = next
				} else {
					e.drop(i)
					i++
				}
				continue
			}
			if truncated && !utf8.FullRuneInString(s[i:]) {
				// A partial rune cut by the input cap is not malformed:
				// stop cleanly without emitting a replacement.
				e.cutAt = i
				break scan
			}
			if !e.replacement(i) {
				break scan
			}
			i++
			continue
		}
		if r >= 0x80 && r <= 0x9f {
			// UTF-8 encoded C1 control.
			next, handled := skipControl(s, i)
			if handled {
				e.drop(i)
				i = next
			} else {
				e.drop(i)
				i += size
			}
			continue
		}
		if r == '\u2028' || r == '\u2029' {
			// Unicode line separators count as line boundaries.
			if !e.mapped(i, lineRepl) {
				break scan
			}
			i += size
			continue
		}
		if unicode.Is(unicode.Cf, r) && r != '\u200c' && r != '\u200d' {
			// Format controls are dropped except ZWNJ/ZWJ.
			e.drop(i)
			i += size
			continue
		}
		if !e.literal(i, size) {
			break scan
		}
		i += size
	}

	stopped := i < len(s)
	truncated = truncated || stopped

	if !e.changed {
		if !truncated {
			return Text{s: s}
		}
		res := s
		if stopped {
			res = s[:e.cutAt]
		}
		out := len(res)
		for out+3 > maxOut && out > 0 {
			_, sz := utf8.DecodeLastRuneInString(res)
			res = res[:len(res)-sz]
			out -= sz
		}
		if out+3 <= maxOut {
			res += "\u2026"
		}
		return Text{s: res, truncated: true}
	}

	if truncated {
		if e.out+3 <= maxOut {
			e.sb.WriteString("\u2026")
		} else {
			res := e.sb.String()
			for e.out+3 > maxOut && e.out > 0 {
				_, sz := utf8.DecodeLastRuneInString(res)
				res = res[:len(res)-sz]
				e.out -= sz
			}
			if e.out+3 <= maxOut {
				res += "\u2026"
			}
			return Text{s: res, truncated: true}
		}
	}
	return Text{s: e.sb.String(), truncated: truncated}
}
