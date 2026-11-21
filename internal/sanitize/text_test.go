// Package sanitize_test black-box tests the text sanitizer against shared
// fixtures and fuzz properties.
package sanitize_test

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/hndrxc/hx/internal/sanitize"
	fix "github.com/hndrxc/hx/internal/testfixture/sanitization"
)

func TestFixtureCases(t *testing.T) {
	cases, err := fix.Cases()
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			log := sanitize.Log(c.Input)
			if log.String() != c.Log {
				t.Errorf("Log: got %q, want %q", log.String(), c.Log)
			}
			label := sanitize.Label(c.Input)
			if label.String() != c.Label {
				t.Errorf("Label: got %q, want %q", label.String(), c.Label)
			}
		})
	}
}

func TestOutputCapExact(t *testing.T) {
	// UTF-8 boundary: exactly at cap, no truncation.
	exact := strings.Repeat("a", 4090) + strings.Repeat("é", 3)
	if g := sanitize.Log(exact); g.Truncated() || len(g.String()) != sanitize.MaxLogBytes {
		t.Errorf("Log exact cap: truncated=%v len=%d", g.Truncated(), len(g.String()))
	}

	// One byte over cap: keep rune-safe prefix, reserve marker.
	over := exact + "x"
	want := strings.Repeat("a", 4090) + "é" + "…"
	if g := sanitize.Log(over); !g.Truncated() || g.String() != want {
		t.Errorf("Log over cap:\n got %q (len %d, truncated %v)\nwant %q (len %d)",
			g.String(), len(g.String()), g.Truncated(), want, len(want))
	}

	// Budget leaves fewer bytes than one rune: rune must be dropped whole.
	short := strings.Repeat("a", 4092) + strings.Repeat("é", 2) + "x"
	wantShort := strings.Repeat("a", 4092) + "…"
	if g := sanitize.Log(short); g.String() != wantShort || !g.Truncated() {
		t.Errorf("Log rune cutoff: got %q want %q", g.String(), wantShort)
	}

	// Multi-byte truncation accounting: 2046 × "é" + marker = 4095 bytes.
	big := strings.Repeat("é", 4096)
	if g := sanitize.Log(big); !g.Truncated() ||
		len(g.String()) != 4095 ||
		strings.Count(g.String(), "é") != 2046 ||
		!strings.HasSuffix(g.String(), "…") {
		t.Errorf("Log multi-byte: len=%d é=%d suffix=%t",
			len(g.String()), strings.Count(g.String(), "é"),
			strings.HasSuffix(g.String(), "…"))
	}
}

func TestLabelCapExact(t *testing.T) {
	exact := strings.Repeat("é", 256)
	if g := sanitize.Label(exact); g.Truncated() || g.String() != exact {
		t.Errorf("Label exact cap: truncated=%v len=%d", g.Truncated(), len(g.String()))
	}
	over := exact + "x"
	want := strings.Repeat("é", 254) + "…" // 508 + 3 = 511 ≤ 512
	if g := sanitize.Label(over); !g.Truncated() || g.String() != want {
		t.Errorf("Label over cap: got %q want %q", g.String(), want)
	}
}

func TestInputCapAndPayloadRemoval(t *testing.T) {
	// Plain oversized input: truncated, valid, bounded.
	huge := strings.Repeat("a", sanitize.MaxInputBytes+4096)
	if g := sanitize.Log(huge); !g.Truncated() || !utf8.ValidString(g.String()) {
		t.Errorf("Log huge input: truncated=%v valid=%v", g.Truncated(), utf8.ValidString(g.String()))
	}

	// Unterminated OSC consumes all payload inside the cap; only the marker survives.
	swallowed := "\x1b]52;c;" + strings.Repeat("B", sanitize.MaxInputBytes+4096)
	if g := sanitize.Log(swallowed); g.String() != "…" || !g.Truncated() {
		t.Errorf("Log swallowed payload: got %q truncated=%v", g.String(), g.Truncated())
	}

	// Label truncates at 512 until marker.
	if g := sanitize.Label(strings.Repeat("x", 1000)); !g.Truncated() || len(g.String()) > sanitize.MaxLabelBytes {
		t.Errorf("Label huge input: truncated=%v len=%d", g.Truncated(), len(g.String()))
	}
	// Regression: a rune split by the input cap is a clean cut, but malformed
	// bytes just before the cap are still replaced. Both keep the ellipsis.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "clean utf8 cutoff",
			// 0xE2 0x82 starts a valid 3-byte rune whose final byte falls past
			// MaxInputBytes; the partial prefix is not malformed.
			in:   strings.Repeat("\x00", sanitize.MaxInputBytes-2) + "\xe2\x82\xac",
			want: "…",
		},
		{
			name: "invalid utf8 prefix",
			// 0xED 0xA0 is an invalid surrogate-prefix pair inside the budget;
			// each byte becomes U+FFFD, then the cap adds the ellipsis.
			in:   strings.Repeat("\x00", sanitize.MaxInputBytes-2) + "\xed\xa0\x80",
			want: "\ufffd\ufffd…",
		},
	}
	for _, c := range cases {
		for _, fn := range []struct {
			name string
			call func(string) sanitize.Text
		}{
			{"Log", sanitize.Log},
			{"Label", sanitize.Label},
		} {
			if g := fn.call(c.in); !g.Truncated() || g.String() != c.want {
				t.Errorf("%s %s: got %q truncated=%v, want %q truncated=true",
					fn.name, c.name, g.String(), g.Truncated(), c.want)
			}
		}
	}
}

func addFixtureSeeds(f *testing.F) {
	cases, err := fix.Cases()
	if err != nil {
		panic(err)
	}
	for _, c := range cases {
		f.Add([]byte(c.Input))
	}
}

func assertNoControls(t *testing.T, s string, allowLF bool) {
	t.Helper()
	for _, r := range s {
		if r == '\n' && allowLF {
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("control U+%04X reached output: %q", r, s)
		}
	}
}

func assertNoBidiFormatting(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if r == 0x200c || r == 0x200d { // ZWNJ / ZWJ allowed
			continue
		}
		if unicode.Is(unicode.Cf, r) {
			t.Fatalf("format character U+%04X in output: %q", r, s)
		}
		if r == 0x061c || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			t.Fatalf("bidi formatting U+%04X in output: %q", r, s)
		}
	}
}

func FuzzLogProperties(f *testing.F) {
	addFixtureSeeds(f)
	f.Fuzz(func(t *testing.T, in []byte) {
		out := sanitize.Log(string(in))
		got := out.String()
		if !utf8.ValidString(got) {
			t.Fatalf("Log emitted invalid UTF-8: %q", got)
		}
		if len(got) > sanitize.MaxLogBytes {
			t.Fatalf("Log exceeded cap: %d > %d", len(got), sanitize.MaxLogBytes)
		}
		assertNoControls(t, got, true)
		assertNoBidiFormatting(t, got)
		if again := sanitize.Log(got); again.String() != got {
			t.Fatalf("Log not idempotent: %q -> %q", got, again.String())
		}
	})
}

func FuzzLabelProperties(f *testing.F) {
	addFixtureSeeds(f)
	f.Fuzz(func(t *testing.T, in []byte) {
		out := sanitize.Label(string(in))
		got := out.String()
		if !utf8.ValidString(got) {
			t.Fatalf("Label emitted invalid UTF-8: %q", got)
		}
		if len(got) > sanitize.MaxLabelBytes {
			t.Fatalf("Label exceeded cap: %d > %d", len(got), sanitize.MaxLabelBytes)
		}
		assertNoControls(t, got, false)
		assertNoBidiFormatting(t, got)
		if again := sanitize.Label(got); again.String() != got {
			t.Fatalf("Label not idempotent: %q -> %q", got, again.String())
		}
	})
}
