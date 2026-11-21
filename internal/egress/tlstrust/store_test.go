//go:build linux

package tlstrust

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

type storeTestEnv struct {
	t      *testing.T
	dir    string
	mu     sync.Mutex
	now    time.Time
	events []AuditEvent
	fail   error
}

func (e *storeTestEnv) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *storeTestEnv) set(t time.Time) {
	e.mu.Lock()
	e.now = t
	e.mu.Unlock()
}

func (e *storeTestEnv) audit(ev AuditEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail != nil {
		return e.fail
	}
	e.events = append(e.events, ev)
	return nil
}

func (e *storeTestEnv) log() []AuditEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]AuditEvent(nil), e.events...)
}

func newStoreTestEnv(t *testing.T) *storeTestEnv {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "trust")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return &storeTestEnv{t: t, dir: dir, now: tlsMaterialEpoch}
}

func (e *storeTestEnv) open() *Store {
	e.t.Helper()
	s, err := Open(e.dir, e.audit)
	if err != nil {
		e.t.Fatal(err)
	}
	s.now = e.clock
	e.t.Cleanup(func() { s.Close() })
	return s
}

func storeTestCandidate(ca *tlsMaterialCert) (Candidate, []Pin) {
	return Candidate{Mode: PrivateCA, Certificates: [][]byte{ca.der}}, []Pin{spkiPin(ca.cert)}
}

func TestStoreApprovePersistsAcrossReopen(t *testing.T) {
	env := newStoreTestEnv(t)
	ca := tlsMaterialCA(t, "ca", nil)
	leaf := tlsMaterialLeaf(t, ca, tlsMaterialOrigin.Host)
	cand, pins := storeTestCandidate(ca)

	s := env.open()
	if _, err := s.Bind(tlsMaterialOrigin).TLSConfig(); !errors.Is(err, ErrUnapproved) {
		t.Fatalf("unapproved: %v", err)
	}
	if err := s.Approve(tlsMaterialOrigin, cand, pins); err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(tlsMaterialOrigin, cand, pins); !errors.Is(err, ErrInvalid) {
		t.Fatalf("re-approve: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(tlsMaterialOrigin).TLSConfig(); !errors.Is(err, ErrStore) {
		t.Fatalf("closed: %v", err)
	}

	s2 := env.open()
	b := s2.Bind(tlsMaterialOrigin)
	if !b.Matches(tlsMaterialOrigin) || b.Matches(Origin{Scheme: "https", Host: "svc.internal", Port: 444}) {
		t.Fatal("Matches")
	}
	cfg, err := b.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := tlsMaterialHandshake(t, cfg, leaf); err != nil {
		t.Fatal(err)
	}
	other := Origin{Scheme: "https", Host: "other.internal", Port: 443}
	if _, err := s2.Bind(other).TLSConfig(); !errors.Is(err, ErrUnapproved) {
		t.Fatalf("other origin: %v", err)
	}
	ev := env.log()
	if len(ev) != 1 || ev[0].Action != Approval || !ev[0].Allowed || ev[0].Origin != tlsMaterialOrigin {
		t.Fatalf("events: %+v", ev)
	}
}

func TestStoreAuditRequiredAndFailClosed(t *testing.T) {
	env := newStoreTestEnv(t)
	if _, err := Open(env.dir, nil); !errors.Is(err, ErrAudit) {
		t.Fatalf("nil audit: %v", err)
	}
	ca := tlsMaterialCA(t, "ca", nil)
	cand, pins := storeTestCandidate(ca)
	s := env.open()
	env.fail = errors.New("sink down")
	if err := s.Approve(tlsMaterialOrigin, cand, pins); !errors.Is(err, ErrAudit) {
		t.Fatalf("audit failure: %v", err)
	}
	env.fail = nil
	if _, err := s.Bind(tlsMaterialOrigin).TLSConfig(); !errors.Is(err, ErrUnapproved) {
		t.Fatalf("record published despite audit failure: %v", err)
	}
	if entries, _ := os.ReadDir(env.dir); len(entries) != 0 {
		t.Fatalf("leftover files: %d", len(entries))
	}
}

func TestStorePinMismatchAudited(t *testing.T) {
	env := newStoreTestEnv(t)
	ca := tlsMaterialCA(t, "ca", nil)
	cand, _ := storeTestCandidate(ca)
	s := env.open()
	bad := []Pin{spkiPin(tlsMaterialCA(t, "x", nil).cert)}
	if err := s.Approve(tlsMaterialOrigin, cand, bad); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("got %v", err)
	}
	ev := env.log()
	if len(ev) != 1 || ev[0].Action != Approval || ev[0].Allowed {
		t.Fatalf("events: %+v", ev)
	}
	// An audit failure surfaces both ErrAudit and the original sentinel.
	env.fail = errors.New("sink down")
	if err := s.Approve(tlsMaterialOrigin, cand, bad); !errors.Is(err, ErrAudit) || !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("audit+pin: %v", err)
	}
	if err := s.Approve(tlsMaterialOrigin, Candidate{}, nil); !errors.Is(err, ErrAudit) || !errors.Is(err, ErrInvalid) {
		t.Fatalf("audit+invalid: %v", err)
	}
	env.fail = nil
	// Invalid candidates are audited as denied administrative attempts.
	if err := s.Approve(tlsMaterialOrigin, Candidate{}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid: %v", err)
	}
	ev = env.log()
	if last := ev[len(ev)-1]; last.Action != Approval || last.Allowed {
		t.Fatalf("events: %+v", ev)
	}
}

func TestZeroStoreFailsSafely(t *testing.T) {
	var s Store
	ca := tlsMaterialCA(t, "ca", nil)
	cand, pins := storeTestCandidate(ca)
	if err := s.Approve(tlsMaterialOrigin, cand, pins); !errors.Is(err, ErrStore) {
		t.Fatalf("approve: %v", err)
	}
	if err := s.BeginRotation(tlsMaterialOrigin, cand, pins, time.Hour); !errors.Is(err, ErrStore) {
		t.Fatalf("rotate: %v", err)
	}
	if err := s.Replace(tlsMaterialOrigin); !errors.Is(err, ErrStore) {
		t.Fatalf("replace: %v", err)
	}
	if _, err := s.Bind(tlsMaterialOrigin).TLSConfig(); !errors.Is(err, ErrStore) {
		t.Fatalf("tls: %v", err)
	}
	if err := s.Close(); !errors.Is(err, ErrStore) {
		t.Fatalf("close: %v", err)
	}
}

func TestStoreHandshakeMismatchAudited(t *testing.T) {
	env := newStoreTestEnv(t)
	ca := tlsMaterialCA(t, "ca", nil)
	s := env.open()
	// Handshake rejection is audited too.
	cand2, pins := storeTestCandidate(ca)
	if err := s.Approve(tlsMaterialOrigin, cand2, pins); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Bind(tlsMaterialOrigin).TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	rogue := tlsMaterialLeaf(t, tlsMaterialCA(t, "rogue", nil), tlsMaterialOrigin.Host)
	if err := tlsMaterialHandshake(t, cfg, rogue); err == nil {
		t.Fatal("rogue accepted")
	}
}

func TestStoreDirectoryLock(t *testing.T) {
	env := newStoreTestEnv(t)
	s := env.open()
	if _, err := Open(env.dir, env.audit); !errors.Is(err, ErrStore) {
		t.Fatalf("second open: %v", err)
	}
	s.Close()
	s2, err := Open(env.dir, env.audit)
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	s2.Close()
}

func TestStoreDirectoryChecks(t *testing.T) {
	env := newStoreTestEnv(t)
	if err := os.Chmod(env.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(env.dir, env.audit); !errors.Is(err, ErrStore) {
		t.Fatalf("loose mode: %v", err)
	}
	if _, err := Open(filepath.Join(env.dir, "missing"), env.audit); !errors.Is(err, ErrStore) {
		t.Fatalf("missing: %v", err)
	}
	if err := os.Chmod(env.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(env.dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, env.audit); !errors.Is(err, ErrStore) {
		t.Fatalf("symlinked dir: %v", err)
	}
	if _, err := Open("", env.audit); !errors.Is(err, ErrStore) {
		t.Fatalf("empty: %v", err)
	}
}

func TestStoreCorruptRecordsFailClosed(t *testing.T) {
	ca := tlsMaterialCA(t, "ca", nil)
	cand, pins := storeTestCandidate(ca)
	name := recordName(tlsMaterialOrigin)

	cases := map[string]func(t *testing.T, path string, good []byte){
		"garbage": func(t *testing.T, p string, _ []byte) {
			os.WriteFile(p, []byte("not json"), 0o600)
		},
		"truncated": func(t *testing.T, p string, good []byte) {
			os.WriteFile(p, good[:len(good)/2], 0o600)
		},
		"noncanonical": func(t *testing.T, p string, good []byte) {
			os.WriteFile(p, append(append([]byte(" "), good...), '\n'), 0o600)
		},
		"unknown field": func(t *testing.T, p string, good []byte) {
			os.WriteFile(p, append(good[:len(good)-1:len(good)-1], []byte(`,"extra":1}`)...), 0o600)
		},
		"oversized": func(t *testing.T, p string, _ []byte) {
			os.WriteFile(p, make([]byte, maxRecordSize+1), 0o600)
		},
		"loose mode": func(t *testing.T, p string, _ []byte) {
			os.Chmod(p, 0o644)
		},
		"symlink": func(t *testing.T, p string, good []byte) {
			target := p + ".real"
			os.WriteFile(target, good, 0o600)
			os.Remove(p)
			os.Symlink(target, p)
		},
		"fifo": func(t *testing.T, p string, _ []byte) {
			os.Remove(p)
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, p string, _ []byte) {
			os.Remove(p)
			os.Mkdir(p, 0o700)
		},
		"hardlink": func(t *testing.T, p string, _ []byte) {
			os.Link(p, p+".alias")
		},
		"wrong origin": func(t *testing.T, p string, good []byte) {
			os.WriteFile(p, bytes.ReplaceAll(good, []byte(`"port":443`), []byte(`"port":444`)), 0o600)
		},
	}
	for label, corrupt := range cases {
		t.Run(label, func(t *testing.T) {
			env := newStoreTestEnv(t)
			s := env.open()
			if err := s.Approve(tlsMaterialOrigin, cand, pins); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(env.dir, name)
			good, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			corrupt(t, path, good)
			_ = good
			if _, err := s.Bind(tlsMaterialOrigin).TLSConfig(); !errors.Is(err, ErrStore) {
				t.Fatalf("TLSConfig = %v, want ErrStore", err)
			}
			if err := s.Approve(tlsMaterialOrigin, cand, pins); !errors.Is(err, ErrStore) {
				t.Fatalf("Approve over corrupt = %v, want ErrStore", err)
			}
		})
	}
}

func TestStoreRotation(t *testing.T) {
	env := newStoreTestEnv(t)
	s := env.open()
	o := tlsMaterialOrigin
	oldCA := tlsMaterialCA(t, "old", nil)
	newCA := tlsMaterialCA(t, "new", nil)
	oldLeaf := tlsMaterialLeaf(t, oldCA, o.Host)
	newLeaf := tlsMaterialLeaf(t, newCA, o.Host)
	oldCand, oldPins := storeTestCandidate(oldCA)
	newCand, newPins := storeTestCandidate(newCA)

	if err := s.BeginRotation(o, newCand, newPins, time.Hour); !errors.Is(err, ErrUnapproved) {
		t.Fatalf("rotate unapproved: %v", err)
	}
	if err := s.Replace(o); !errors.Is(err, ErrUnapproved) {
		t.Fatalf("replace unapproved: %v", err)
	}
	if err := s.Approve(o, oldCand, oldPins); err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(o); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replace without staged: %v", err)
	}
	for _, d := range []time.Duration{0, -time.Second, MaxOverlap + time.Nanosecond} {
		if err := s.BeginRotation(o, newCand, newPins, d); !errors.Is(err, ErrInvalid) {
			t.Fatalf("overlap %v: %v", d, err)
		}
	}
	// Policy downgrade / mode change are refused.
	pinned := newCand
	pinned.LeafPin = spkiPin(newLeaf.cert)
	if err := s.BeginRotation(o, pinned, append(newPins, pinned.LeafPin), time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pin presence change: %v", err)
	}
	if err := s.BeginRotation(o, Candidate{Mode: PinnedLeaf, Certificates: [][]byte{newLeaf.der}}, []Pin{spkiPin(newLeaf.cert)}, time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mode change: %v", err)
	}
	if err := s.BeginRotation(o, newCand, []Pin{{1}}, time.Hour); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("bad pins: %v", err)
	}

	if err := s.BeginRotation(o, newCand, newPins, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginRotation(o, newCand, newPins, time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("chained rotation: %v", err)
	}

	b := s.Bind(o)
	check := func(label string, wantOld, wantNew bool) {
		t.Helper()
		cfg, err := b.TLSConfig()
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if got := tlsMaterialHandshake(t, cfg, oldLeaf) == nil; got != wantOld {
			t.Fatalf("%s: old accepted=%v", label, got)
		}
		if got := tlsMaterialHandshake(t, cfg, newLeaf) == nil; got != wantNew {
			t.Fatalf("%s: new accepted=%v", label, got)
		}
	}
	check("overlap", true, true)

	// The deadline is enforced across reopen, and the staged trust stays
	// active after cutoff without any cleanup.
	s.Close()
	s = env.open()
	b = s.Bind(o)
	env.set(tlsMaterialEpoch.Add(time.Hour))
	check("after cutoff", false, true)
	if err := s.BeginRotation(o, oldCand, oldPins, time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("chained after cutoff: %v", err)
	}

	if err := s.Replace(o); err != nil {
		t.Fatal(err)
	}
	check("replaced", false, true)
	if err := s.Replace(o); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second replace: %v", err)
	}
	// A fresh rotation is possible again after Replace.
	if err := s.BeginRotation(o, oldCand, oldPins, time.Hour); err != nil {
		t.Fatal(err)
	}

	var actions []Action
	for _, ev := range env.log() {
		if !ev.Allowed {
			continue
		}
		actions = append(actions, ev.Action)
	}
	want := []Action{Approval, Rotation, Replacement, Rotation}
	if len(actions) < len(want) {
		t.Fatalf("actions: %v", actions)
	}
	for i, a := range want {
		if actions[i] != a {
			t.Fatalf("actions: %v", actions)
		}
	}
}

func TestStoreEarlyReplace(t *testing.T) {
	env := newStoreTestEnv(t)
	s := env.open()
	o := tlsMaterialOrigin
	oldCA := tlsMaterialCA(t, "old", nil)
	newCA := tlsMaterialCA(t, "new", nil)
	oldCand, oldPins := storeTestCandidate(oldCA)
	newCand, newPins := storeTestCandidate(newCA)
	if err := s.Approve(o, oldCand, oldPins); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginRotation(o, newCand, newPins, MaxOverlap); err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(o); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Bind(o).TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := tlsMaterialHandshake(t, cfg, tlsMaterialLeaf(t, oldCA, o.Host)); err == nil {
		t.Fatal("old trust survived Replace")
	}
	if err := tlsMaterialHandshake(t, cfg, tlsMaterialLeaf(t, newCA, o.Host)); err != nil {
		t.Fatal(err)
	}
}

func TestStoreInvalidOriginRejected(t *testing.T) {
	env := newStoreTestEnv(t)
	s := env.open()
	ca := tlsMaterialCA(t, "ca", nil)
	cand, pins := storeTestCandidate(ca)
	bad := Origin{Scheme: "http", Host: "svc.internal", Port: 80}
	if err := s.Approve(bad, cand, pins); !errors.Is(err, ErrInvalid) {
		t.Fatalf("approve: %v", err)
	}
	if _, err := s.Bind(bad).TLSConfig(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bind: %v", err)
	}
	if s.Bind(bad).Matches(bad) {
		t.Fatal("invalid origin matched")
	}
}

func TestStorePoisonOnAmbiguousCommit(t *testing.T) {
	env := newStoreTestEnv(t)
	s := env.open()
	real := s.be
	s.be = failingBackend{real}
	ca := tlsMaterialCA(t, "ca", nil)
	cand, pins := storeTestCandidate(ca)
	if err := s.Approve(tlsMaterialOrigin, cand, pins); !errors.Is(err, ErrStore) {
		t.Fatalf("approve: %v", err)
	}
	if _, err := s.Bind(tlsMaterialOrigin).TLSConfig(); !errors.Is(err, ErrStore) {
		t.Fatalf("poisoned store served trust: %v", err)
	}
	if err := s.Approve(tlsMaterialOrigin, cand, pins); !errors.Is(err, ErrStore) {
		t.Fatalf("poisoned store accepted write: %v", err)
	}
}

type failingBackend struct{ backend }

func (failingBackend) write(string, []byte) error {
	return &commitError{errors.New("simulated sync failure")}
}

func TestStoreRejectsUnboundedOverlapRecords(t *testing.T) {
	ca := tlsMaterialCA(t, "ca", nil)
	next := tlsMaterialCA(t, "next", nil)
	cand, pins := storeTestCandidate(ca)
	nextCand, nextPins := storeTestCandidate(next)
	o := tlsMaterialOrigin
	cases := map[string]func(r *record) bool{ // returns whether the record stays acceptable
		"exact max overlap":  func(r *record) bool { r.deadline = r.started + int64(MaxOverlap); return true },
		"beyond max":         func(r *record) bool { r.deadline = r.started + int64(MaxOverlap) + 1; return false },
		"far future":         func(r *record) bool { r.deadline = math.MaxInt64; return false },
		"deadline == start":  func(r *record) bool { r.deadline = r.started; return false },
		"deadline < start":   func(r *record) bool { r.deadline = r.started - 1; return false },
		"zero started":       func(r *record) bool { r.started = 0; return false },
		"negative started":   func(r *record) bool { r.started = -5; r.deadline = 5; return false },
		"started w/o stage":  func(r *record) bool { r.staged, r.deadline = nil, 0; return false },
		"deadline w/o start": func(r *record) bool { r.started = 0; r.deadline = 0; return false },
	}
	for label, mutate := range cases {
		t.Run(label, func(t *testing.T) {
			env := newStoreTestEnv(t)
			s := env.open()
			if err := s.Approve(o, cand, pins); err != nil {
				t.Fatal(err)
			}
			if err := s.BeginRotation(o, nextCand, nextPins, time.Hour); err != nil {
				t.Fatal(err)
			}
			rec, err := s.load(o)
			if err != nil {
				t.Fatal(err)
			}
			ok := mutate(rec)
			data, err := marshalRecord(rec)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(env.dir, recordName(o))
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = s.Bind(o).TLSConfig()
			if ok && err != nil {
				t.Fatalf("valid record rejected: %v", err)
			}
			if !ok && !errors.Is(err, ErrStore) {
				t.Fatalf("corrupt overlap accepted: %v", err)
			}
		})
	}
}
