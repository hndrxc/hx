package sanitize

import "unicode/utf8"

const (
	asciiCAN = 0x18
	asciiSUB = 0x1a
	asciiBEL = 0x07
	asciiESC = 0x1b

	c1DCS = 0x90
	c1SOS = 0x98
	c1CSI = 0x9b
	c1ST  = 0x9c
	c1OSC = 0x9d
	c1PM  = 0x9e
	c1APC = 0x9f
)

// c1At reports a C1 control at s[i], either a raw byte 0x80-0x9f that is not
// part of valid UTF-8 (callers invoke at rune starts) or the encoded form
// U+0080-U+009F. n is the byte length consumed.
func c1At(s string, i int) (c byte, n int, ok bool) {
	if i >= len(s) {
		return 0, 0, false
	}
	b := s[i]
	if b >= 0x80 && b <= 0x9f {
		return b, 1, true
	}
	if b == 0xc2 && i+1 < len(s) && s[i+1] >= 0x80 && s[i+1] <= 0x9f {
		return s[i+1], 2, true
	}
	return 0, 0, false
}

// skipControl consumes one terminal control construct starting at s[i].
// It must be called at a rune boundary. If handled, next > i. Malformed
// sequences stop before the offending byte so the caller reprocesses it;
// unterminated sequences consume the remainder of s. It does not allocate.
func skipControl(s string, i int) (next int, handled bool) {
	if i < 0 || i >= len(s) {
		return i, false
	}
	if s[i] == asciiESC {
		return skipEscape(s, i+1), true
	}
	c, n, ok := c1At(s, i)
	if !ok {
		return i, false
	}
	return skipIntroducer(s, i+n, c), true
}

// skipEscape handles the bytes following a 7-bit ESC at s[j-1].
func skipEscape(s string, j int) int {
	if j >= len(s) {
		return len(s)
	}
	switch b := s[j]; b {
	case '[':
		return skipIntroducer(s, j+1, c1CSI)
	case ']':
		return skipIntroducer(s, j+1, c1OSC)
	case 'P':
		return skipIntroducer(s, j+1, c1DCS)
	case 'X':
		return skipIntroducer(s, j+1, c1SOS)
	case '^':
		return skipIntroducer(s, j+1, c1PM)
	case '_':
		return skipIntroducer(s, j+1, c1APC)
	case asciiCAN, asciiSUB:
		return j + 1
	}
	// Generic: intermediates 0x20-0x2f then a final 0x30-0x7e.
	for j < len(s) && s[j] >= 0x20 && s[j] <= 0x2f {
		j++
	}
	if j >= len(s) {
		return len(s)
	}
	switch b := s[j]; {
	case b >= 0x30 && b <= 0x7e:
		return j + 1
	case b == asciiCAN || b == asciiSUB:
		return j + 1
	}
	return j // malformed: reprocess this byte
}

// skipIntroducer consumes the body of the construct named by C1 code c, with
// j just past the introducer.
func skipIntroducer(s string, j int, c byte) int {
	switch c {
	case c1CSI:
		return skipCSI(s, j)
	case c1OSC:
		return skipString(s, j, true)
	case c1DCS, c1SOS, c1PM, c1APC:
		return skipString(s, j, false)
	}
	return j // other C1 (including ST) is a lone control
}

func skipCSI(s string, j int) int {
	for j < len(s) {
		b := s[j]
		switch {
		case b >= 0x20 && b <= 0x3f:
			j++
		case b >= 0x40 && b <= 0x7e:
			return j + 1
		case b == asciiCAN || b == asciiSUB:
			return j + 1
		case b == asciiESC:
			return j // ESC restarts: reprocess it
		case b < 0x20 || b == 0x7f:
			j++ // strip embedded C0 (other than ESC/CAN/SUB) and DEL
		default:
			return j // invalid: let caller reprocess
		}
	}
	return len(s)
}

// skipString consumes a string construct (OSC, DCS, SOS, PM, APC) body until
// its terminator: ST (ESC \ or C1 0x9c), CAN/SUB, or BEL for OSC. Embedded
// non-ST ESC bytes are discarded, not treated as terminations. Unterminated
// sequences consume the remainder of s.
func skipString(s string, j int, bel bool) int {
	for j < len(s) {
		b := s[j]
		switch {
		case b == asciiCAN || b == asciiSUB:
			return j + 1
		case b == asciiBEL && bel:
			return j + 1
		case b == asciiESC:
			if j+1 >= len(s) {
				return len(s)
			}
			if s[j+1] == '\\' {
				return j + 2
			}
			j++ // discard embedded non-ST ESC
		case b < utf8.RuneSelf:
			j++
		case b == c1ST:
			return j + 1
		default:
			r, size := utf8.DecodeRuneInString(s[j:])
			if r == 0x9c && size == 2 {
				return j + 2
			}
			j += size
		}
	}
	return len(s)
}
