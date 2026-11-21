//go:build linux

package tlsaudit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hndrxc/hx/internal/egress/tlstrust"
	"github.com/hndrxc/hx/internal/hub/audit"
)

var (
	opID  = audit.ID{1, 2, 3}
	intID = audit.ID{4, 5, 6}
)

func openLog(t *testing.T) (*audit.Log, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "audit.jsonl")
	l, err := audit.Open(p, audit.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return l, p
}

func TestAdapterRecordsVerifiableChain(t *testing.T) {
	l, path := openLog(t)
	hooks := audit.NewHooks(l)
	fn, err := New(&hooks, opID, intID)
	if err != nil {
		t.Fatal(err)
	}
	origin := tlstrust.Origin{Scheme: "https", Host: "secret.internal.example", Port: 8443}
	at := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	events := []tlstrust.AuditEvent{
		{At: at, Origin: origin, Action: tlstrust.Approval, Allowed: true},
		{At: at.Add(time.Second), Origin: origin, Action: tlstrust.Rotation, Allowed: false},
		{At: at.Add(2 * time.Second), Origin: origin, Action: tlstrust.Replacement, Allowed: true},
		{At: at.Add(3 * time.Second), Origin: origin, Action: tlstrust.PinMismatch, Allowed: false},
	}
	for _, ev := range events {
		if err := fn(ev); err != nil {
			t.Fatalf("%s: %v", ev.Action, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	head, err := audit.Verify(bytes.NewReader(data), nil)
	if err != nil || head.Sequence != uint64(len(events)) {
		t.Fatalf("verify: %v %+v", err, head)
	}
	if _, err := audit.Verify(bytes.NewReader(data), &head); err != nil {
		t.Fatalf("verify anchored: %v", err)
	}
	for _, s := range []string{"secret.internal.example", "https", "origin", "host"} {
		if strings.Contains(string(data), s) {
			t.Errorf("log contains %q", s)
		}
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	want := []struct {
		action, actorKind, actorID, outcome string
	}{
		{"tls_trust_approval", "operator", opID.String(), "allowed"},
		{"tls_trust_rotation", "operator", opID.String(), "denied"},
		{"tls_trust_replacement", "operator", opID.String(), "allowed"},
		{"tls_pin_mismatch", "integration", intID.String(), "denied"},
	}
	corrs := map[string]bool{}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		if len(m) != 11 {
			t.Errorf("line %d has %d members: %v", i, len(m), m)
		}
		dump := line
		for _, w := range []string{want[i].action, want[i].actorKind, want[i].actorID, want[i].outcome, intID.String()} {
			if !strings.Contains(dump, w) {
				t.Errorf("line %d missing %q: %s", i, w, line)
			}
		}
		if !strings.Contains(line, events[i].At.Format(time.RFC3339Nano)) {
			t.Errorf("line %d timestamp not from store: %s", i, line)
		}
		for k, v := range m {
			if strings.Contains(k, "correl") {
				s, _ := v.(string)
				corrs[s] = true
			}
		}
	}
	if len(corrs) != len(events) {
		t.Errorf("correlators not unique: %d", len(corrs))
	}
}

func TestAdapterFailsClosed(t *testing.T) {
	l, path := openLog(t)
	defer l.Close()
	hooks := audit.NewHooks(l)
	if _, err := New(nil, opID, intID); !errors.Is(err, ErrInvalid) {
		t.Errorf("nil hooks: %v", err)
	}
	if _, err := New(&hooks, audit.ID{}, intID); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero operator: %v", err)
	}
	if _, err := New(&hooks, opID, audit.ID{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero integration: %v", err)
	}
	fn, err := New(&hooks, opID, intID)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	for name, ev := range map[string]tlstrust.AuditEvent{
		"unknown action":       {At: at, Action: "bogus", Allowed: true},
		"allowed pin mismatch": {At: at, Action: tlstrust.PinMismatch, Allowed: true},
		"zero time":            {Action: tlstrust.Approval, Allowed: true},
	} {
		if err := fn(ev); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	var zero audit.Hooks
	fz, err := New(&zero, opID, intID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fz(tlstrust.AuditEvent{At: at, Action: tlstrust.Approval, Allowed: true}); !errors.Is(err, audit.ErrHooksUnconfigured) {
		t.Errorf("zero hooks: %v", err)
	}
	// Closed log: append fails and the error propagates.
	l2, _ := openLog(t)
	h2 := audit.NewHooks(l2)
	f2, _ := New(&h2, opID, intID)
	l2.Close()
	if err := f2(tlstrust.AuditEvent{At: at, Action: tlstrust.Approval, Allowed: true}); !errors.Is(err, audit.ErrLogClosed) {
		t.Errorf("closed log: %v", err)
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Errorf("rejected events were appended: %q", data)
	}
}
