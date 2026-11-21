package client

import (
	"errors"
	"strings"
	"testing"
)

func TestDistinctIDsSameRenderedText(t *testing.T) {
	a, err := NewTextView("src-1", "same", "body")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTextView("src-2", "same", "body")
	if err != nil {
		t.Fatal(err)
	}
	if a.Title().String() != b.Title().String() || a.Body().String() != b.Body().String() {
		t.Fatal("rendered text differs")
	}
	if a.SourceID() == b.SourceID() || a.SourceID().String() == b.SourceID().String() {
		t.Fatal("ids must stay distinct")
	}
}

func TestSourceIDExactAndNotFromLabel(t *testing.T) {
	v, err := NewTextView("A.b_c:d-9", "other", "")
	if err != nil {
		t.Fatal(err)
	}
	if v.SourceID().String() != "A.b_c:d-9" {
		t.Fatalf("got %q", v.SourceID().String())
	}
	if _, err := NewTextView(strings.Repeat("a", 128), "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestSourceIDRejectionRedacted(t *testing.T) {
	bad := []string{"", strings.Repeat("a", 129), "-a", ".a", "_a", ":a", "a/b", "a b", "a\n", "a\x1b[31m", "a\x00", "é", "a\u202e", "a\x7f", "a\x9b"}
	for _, in := range bad {
		_, err := NewTextView(in, "t", "b")
		if !errors.Is(err, ErrSourceID) {
			t.Fatalf("%q: err=%v", in, err)
		}
		if in != "" && strings.Contains(err.Error(), in) {
			t.Fatalf("error leaks input %q", in)
		}
	}
}

func TestInertTextAndControls(t *testing.T) {
	v, err := NewTextView("id1", "<b>x</b>\x1b]8;;http://example.invalid\x07\nok", "<a href=\"http://example.invalid\">l</a>\x1b[31mred\x00\x07")
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Title().String(); got != "<b>x</b> ok" && got != "<b>x</b>ok" {
		t.Fatalf("title %q", got)
	}
	body := v.Body().String()
	if !strings.Contains(body, "<a href=\"http://example.invalid\">l</a>") {
		t.Fatalf("markup should remain plain text: %q", body)
	}
	for _, s := range []string{v.Title().String(), body} {
		for _, r := range s {
			if r < 0x20 && r != '\n' || r == 0x7f || r >= 0x80 && r <= 0x9f {
				t.Fatalf("control in %q", s)
			}
		}
	}
}
