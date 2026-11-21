//go:build linux

package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testEvent(n byte) Event {
	return Event{
		At:            time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ActorKind:     ActorOperator,
		ActorID:       ID{1, n},
		Action:        ActionVaultUnseal,
		Outcome:       OutcomeAllowed,
		CorrelationID: ID{2, n},
	}
}

func logPath(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "audit.jsonl")
}

func mustOpen(t *testing.T, path string, o OpenOptions) *Log {
	t.Helper()
	l, err := Open(path, o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return l
}

func appendN(t *testing.T, l *Log, n int) Checkpoint {
	t.Helper()
	var cp Checkpoint
	for i := range n {
		var err error
		if cp, err = l.Append(testEvent(byte(i + 1))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	return cp
}

func TestAppendReopenDurableHistory(t *testing.T) {
	p := logPath(t)
	l := mustOpen(t, p, OpenOptions{})
	cp := appendN(t, l, 3)
	if cp.Sequence != 3 {
		t.Fatalf("sequence = %d", cp.Sequence)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l = mustOpen(t, p, OpenOptions{Anchor: &cp})
	next, err := l.Append(testEvent(9))
	if err != nil || next.Sequence != 4 {
		t.Fatalf("append after reopen: %v %+v", err, next)
	}
	l.Close()
	data, _ := os.ReadFile(p)
	head, err := Verify(bytes.NewReader(data), &cp)
	if err != nil || head != next {
		t.Fatalf("verify: %v %+v", err, head)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestConcurrentAppends(t *testing.T) {
	p := logPath(t)
	l := mustOpen(t, p, OpenOptions{})
	const n = 32
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := l.Append(testEvent(byte(i + 1))); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	l.Close()
	data, _ := os.ReadFile(p)
	head, err := Verify(bytes.NewReader(data), nil)
	if err != nil || head.Sequence != n {
		t.Fatalf("verify: %v %+v", err, head)
	}
}

func TestInvalidEventReservesNoSequence(t *testing.T) {
	l := mustOpen(t, logPath(t), OpenOptions{})
	defer l.Close()
	if _, err := l.Append(Event{}); err == nil {
		t.Fatal("expected error for invalid event")
	}
	cp, err := l.Append(testEvent(1))
	if err != nil || cp.Sequence != 1 {
		t.Fatalf("%v %+v", err, cp)
	}
}

func TestLockContention(t *testing.T) {
	p := logPath(t)
	l := mustOpen(t, p, OpenOptions{})
	if _, err := Open(p, OpenOptions{}); err == nil {
		t.Fatal("second Open succeeded while locked")
	}
	l.Close()
	mustOpen(t, p, OpenOptions{}).Close()
}

func TestClosedRefusesAppend(t *testing.T) {
	l := mustOpen(t, logPath(t), OpenOptions{})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(testEvent(1)); err != ErrLogClosed {
		t.Fatalf("got %v", err)
	}
}

func TestWriteFailurePoisons(t *testing.T) {
	p := logPath(t)
	l := mustOpen(t, p, OpenOptions{})
	cp := appendN(t, l, 1)
	// Close the underlying descriptor so the next write fails for real.
	if err := l.f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(testEvent(2)); err == nil || err == ErrLogPoisoned {
		t.Fatalf("expected write error, got %v", err)
	}
	if _, err := l.Append(testEvent(3)); err != ErrLogPoisoned {
		t.Fatalf("got %v, want ErrLogPoisoned", err)
	}
	l.Close()
	l2 := mustOpen(t, p, OpenOptions{Anchor: &cp})
	defer l2.Close()
	if l2.head != cp {
		t.Fatalf("reopened head %+v, want %+v", l2.head, cp)
	}
}

func TestMissingFileNotCreated(t *testing.T) {
	p := logPath(t)
	cp := Checkpoint{Sequence: 1, Hash: strings.Repeat("1", 64)}
	g := Genesis()
	for name, o := range map[string]OpenOptions{
		"anchor":        {Anchor: &cp},
		"recover":       {Anchor: &cp, RecoverTail: true},
		"genesis+recov": {Anchor: &g, RecoverTail: true},
	} {
		if _, err := Open(p, o); err == nil {
			t.Fatalf("%s: missing file accepted", name)
		}
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s: path created: %v", name, err)
		}
	}
	if _, err := Open(p, OpenOptions{Anchor: &Checkpoint{Sequence: 0, Hash: strings.Repeat("1", 64)}}); err == nil {
		t.Fatal("invalid anchor accepted")
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("invalid anchor created path: %v", err)
	}
	mustOpen(t, p, OpenOptions{Anchor: &g}).Close()
	if _, err := os.Lstat(p); err != nil {
		t.Fatalf("genesis-anchored open did not create: %v", err)
	}
}

func TestPermissionsAndSymlink(t *testing.T) {
	p := logPath(t)
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p, OpenOptions{}); err == nil {
		t.Fatal("accepted mode 0644")
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	mustOpen(t, p, OpenOptions{}).Close()

	link := filepath.Join(filepath.Dir(p), "link.jsonl")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, OpenOptions{}); err == nil {
		t.Fatal("followed symlink")
	}

	fifo := filepath.Join(filepath.Dir(p), "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(fifo, OpenOptions{}); err == nil {
		t.Fatal("accepted fifo")
	}
}

func TestRecoverTailRequiresAnchor(t *testing.T) {
	if _, err := Open(logPath(t), OpenOptions{RecoverTail: true}); err == nil {
		t.Fatal("recovery without anchor accepted")
	}
}

// crashFixture writes 3 good records plus a torn partial record.
func crashFixture(t *testing.T) (path string, good []byte, cps []Checkpoint) {
	t.Helper()
	path = logPath(t)
	l := mustOpen(t, path, OpenOptions{})
	for i := 1; i <= 3; i++ {
		cp, err := l.Append(testEvent(byte(i)))
		if err != nil {
			t.Fatal(err)
		}
		cps = append(cps, cp)
	}
	l.Close()
	good, _ = os.ReadFile(path)
	frame, _, err := encode(testEvent(4), cps[2])
	if err != nil {
		t.Fatal(err)
	}
	torn := append(append([]byte{}, good...), frame[:len(frame)/2]...)
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, good, cps
}

func TestTornTailRecovery(t *testing.T) {
	path, good, cps := crashFixture(t)
	before, _ := os.ReadFile(path)

	// No opt-in: refused, file untouched.
	if _, err := Open(path, OpenOptions{Anchor: &cps[2]}); err == nil {
		t.Fatal("torn tail accepted without opt-in")
	}
	// Opt-in without anchor: refused.
	if _, err := Open(path, OpenOptions{RecoverTail: true}); err == nil {
		t.Fatal("recovery without anchor")
	}
	// Anchor beyond the valid prefix: refused.
	future := Checkpoint{Sequence: 4, Hash: cps[2].Hash}
	if _, err := Open(path, OpenOptions{Anchor: &future, RecoverTail: true}); err == nil {
		t.Fatal("too-new anchor accepted")
	}
	// Mismatched anchor: refused.
	bad := Checkpoint{Sequence: 2, Hash: cps[2].Hash}
	if _, err := Open(path, OpenOptions{Anchor: &bad, RecoverTail: true}); err == nil {
		t.Fatal("mismatched anchor accepted")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Fatal("refused open modified the file")
	}

	// Old-good anchor (below head) with recovery preserves all complete frames.
	l := mustOpen(t, path, OpenOptions{Anchor: &cps[0], RecoverTail: true})
	if after, _ := os.ReadFile(path); !bytes.Equal(after, good) {
		t.Fatal("recovery did not truncate exactly to valid prefix")
	}
	cp, err := l.Append(testEvent(7))
	if err != nil || cp.Sequence != 4 {
		t.Fatalf("append after recovery: %v %+v", err, cp)
	}
	l.Close()
}

func TestTornTailRecoveryGenesisAnchor(t *testing.T) {
	path, good, _ := crashFixture(t)
	g := Genesis()
	mustOpen(t, path, OpenOptions{Anchor: &g, RecoverTail: true}).Close()
	if after, _ := os.ReadFile(path); !bytes.Equal(after, good) {
		t.Fatal("not truncated to valid prefix")
	}
}

func TestCompleteCorruptionPreserved(t *testing.T) {
	path, good, cps := crashFixture(t)
	bad := append([]byte{}, good...)
	bad[len(bad)/2] ^= 0x01
	torn := append(bad, []byte(`{"version":1`)...)
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, OpenOptions{Anchor: &cps[0], RecoverTail: true}); err == nil {
		t.Fatal("corruption accepted")
	}
	if _, err := Open(path, OpenOptions{}); err == nil {
		t.Fatal("corruption accepted unanchored")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, torn) {
		t.Fatal("corrupt file was modified")
	}
}
