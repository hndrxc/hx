package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func vID(b byte) ID {
	var id ID
	for i := range id {
		id[i] = b + byte(i)
	}
	return id
}

func vEvent(n int) Event {
	return Event{
		At:            time.Date(2026, 1, 2, 3, 4, 5, n, time.UTC),
		ActorKind:     ActorOperator,
		ActorID:       vID(1),
		Action:        ActionVaultUnseal,
		Outcome:       OutcomeAllowed,
		CorrelationID: vID(byte(0x40 + n)),
	}
}

// vChain returns n frames and the checkpoint after each (index 0 is genesis).
func vChain(t *testing.T, n int) ([][]byte, []Checkpoint) {
	t.Helper()
	cps := []Checkpoint{Genesis()}
	var frames [][]byte
	for i := 1; i <= n; i++ {
		f, cp, err := encode(vEvent(i), cps[i-1])
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, f)
		cps = append(cps, cp)
	}
	return frames, cps
}

func vJoin(frames ...[]byte) []byte { return bytes.Join(frames, nil) }

func TestFixedV1Format(t *testing.T) {
	ev := Event{
		At:            time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC),
		ActorKind:     ActorOperator,
		ActorID:       ID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		Action:        ActionVaultUnseal,
		Outcome:       OutcomeAllowed,
		CorrelationID: ID{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
	}
	const wantBody = `{"version":1,"sequence":1,"previous":"0000000000000000000000000000000000000000000000000000000000000000","time":"2026-01-02T03:04:05.123456789Z","actor_kind":"operator","actor_id":"00112233445566778899aabbccddeeff","integration_id":"00000000000000000000000000000000","action":"vault_unseal","outcome":"allowed","correlation_id":"ffeeddccbbaa99887766554433221100"}`
	const wantHash = "f4725e4079a69972267c6f0153be9a22493ca926e2f41dd28e9d22ebb8256c85"
	sum := sha256.Sum256([]byte(wantBody))
	if hex.EncodeToString(sum[:]) != wantHash {
		t.Fatal("test fixture digest out of date")
	}
	want := wantBody[:len(wantBody)-1] + `,"hash":"` + wantHash + "\"}\n"
	got, cp, err := encode(ev, Genesis())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("frame mismatch:\n got %s\nwant %s", got, want)
	}
	if cp != (Checkpoint{Sequence: 1, Hash: wantHash}) {
		t.Fatalf("checkpoint = %+v", cp)
	}
	head, err := Verify(strings.NewReader(want), nil)
	if err != nil || head != cp {
		t.Fatalf("Verify = %+v, %v", head, err)
	}
	if g := Genesis(); g.Sequence != 0 || g.Hash != strings.Repeat("0", 64) {
		t.Fatalf("genesis = %+v", g)
	}
}

func TestEncodeNormalizesTimeToUTC(t *testing.T) {
	ev := vEvent(1)
	ev.At = ev.At.In(time.FixedZone("x", 3600))
	a, _, err := encode(ev, Genesis())
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := encode(vEvent(1), Genesis())
	if !bytes.Equal(a, b) {
		t.Fatal("non-UTC time encoded differently")
	}
}

func TestVerifyValidChain(t *testing.T) {
	frames, cps := vChain(t, 5)
	head, err := Verify(bytes.NewReader(vJoin(frames...)), nil)
	if err != nil || head != cps[5] {
		t.Fatalf("Verify = %+v, %v", head, err)
	}
	head, err = Verify(bytes.NewReader(nil), nil)
	if err != nil || head != Genesis() {
		t.Fatalf("empty Verify = %+v, %v", head, err)
	}
}

func TestInvalidEvents(t *testing.T) {
	bad := map[string]func(*Event){
		"zero time":           func(e *Event) { e.At = time.Time{} },
		"bad actor kind":      func(e *Event) { e.ActorKind = "root" },
		"bad action":          func(e *Event) { e.Action = "x" },
		"bad outcome":         func(e *Event) { e.Outcome = "x" },
		"zero actor":          func(e *Event) { e.ActorID = ID{} },
		"zero correlation":    func(e *Event) { e.CorrelationID = ID{} },
		"unknown allowed":     func(e *Event) { e.ActorKind = ActorUnknown },
		"secret no integrate": func(e *Event) { e.Action = ActionSecretAccess },
	}
	for name, mut := range bad {
		ev := vEvent(1)
		mut(&ev)
		if _, _, err := encode(ev, Genesis()); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	ev := vEvent(1)
	ev.ActorKind = ActorUnknown
	ev.Outcome = OutcomeDenied
	if _, _, err := encode(ev, Genesis()); err != nil {
		t.Fatalf("unknown denied: %v", err)
	}
}

func TestInteriorTamperingDetected(t *testing.T) {
	frames, _ := vChain(t, 4)
	edited := bytes.Replace(frames[1], []byte(`"allowed"`), []byte(`"denied"`), 1)
	if bytes.Equal(edited, frames[1]) {
		t.Fatal("edit no-op")
	}
	cases := map[string][]byte{
		"edited":   vJoin(frames[0], edited, frames[2], frames[3]),
		"reorder":  vJoin(frames[0], frames[2], frames[1], frames[3]),
		"removed":  vJoin(frames[0], frames[2], frames[3]),
		"duplicat": vJoin(frames[0], frames[1], frames[1], frames[2]),
		"first":    vJoin(frames[1], frames[2], frames[3]),
	}
	for name, data := range cases {
		_, err := Verify(bytes.NewReader(data), nil)
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: err = %v", name, err)
		}
		if _, _, err := scan(bytes.NewReader(data), nil); errors.Is(err, ErrTornTail) {
			t.Errorf("%s: must not permit recovery", name)
		}
	}
}

func TestNonCanonicalFramesRejected(t *testing.T) {
	frames, _ := vChain(t, 1)
	f := string(frames[0])
	variants := map[string]string{
		"whitespace":    strings.Replace(f, `"version":1,`, `"version": 1, `, 1),
		"duplicate key": strings.Replace(f, `{"version":1,`, `{"version":1,"version":1,`, 1),
		"unknown key":   strings.Replace(f, `,"hash"`, `,"extra":1,"hash"`, 1),
		"reordered":     strings.Replace(f, `{"version":1,"sequence":1,`, `{"sequence":1,"version":1,`, 1),
		"time offset":   strings.Replace(f, `.000000001Z`, `.000000001+00:00`, 1),
		"time padded":   strings.Replace(f, `.000000001Z`, `.0000000010Z`, 1),
		"unicode esc":   strings.Replace(f, `"operator"`, `"operat\u006fr"`, 1),
		"crlf":          strings.TrimSuffix(f, "\n") + "\r\n",
		"trailing":      strings.TrimSuffix(f, "\n") + " \n",
		"version 2":     strings.Replace(f, `"version":1`, `"version":2`, 1),
		"empty line":    "\n",
		"not json":      "garbage\n",
	}
	up := strings.Replace(f, `"actor_id":"0102030405060708090a0b0c0d0e0f10"`, `"actor_id":"0102030405060708090A0B0C0D0E0F10"`, 1)
	if up == f {
		t.Fatal("uppercase variant no-op")
	}
	variants["upper hex"] = up
	for name, v := range variants {
		if name == "time padded" || name == "time offset" {
			if v == f {
				t.Fatalf("%s: no-op variant", name)
			}
		}
		_, err := Verify(strings.NewReader(v), nil)
		if err == nil || errors.Is(err, ErrTornTail) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestRollbackAndAnchors(t *testing.T) {
	frames, cps := vChain(t, 4)
	full := vJoin(frames...)

	// Valid older anchor, head beyond it.
	old := cps[2]
	head, err := Verify(bytes.NewReader(full), &old)
	if err != nil || head != cps[4] {
		t.Fatalf("old anchor: %+v, %v", head, err)
	}
	// Genesis anchor is always satisfied.
	g := Genesis()
	if _, err := Verify(bytes.NewReader(full), &g); err != nil {
		t.Fatalf("genesis anchor: %v", err)
	}
	// Anchor at head.
	if _, err := Verify(bytes.NewReader(full), &cps[4]); err != nil {
		t.Fatalf("head anchor: %v", err)
	}
	// Clean rollback of the tail is a valid chain, but not past the anchor.
	rolled := vJoin(frames[:2]...)
	if h, err := Verify(bytes.NewReader(rolled), nil); err != nil || h != cps[2] {
		t.Fatalf("unanchored rollback should verify: %+v, %v", h, err)
	}
	if _, err := Verify(bytes.NewReader(rolled), &cps[3]); !errors.Is(err, ErrAnchorMissing) {
		t.Fatalf("anchored rollback: %v", err)
	}
	if _, err := Verify(bytes.NewReader(nil), &cps[1]); !errors.Is(err, ErrAnchorMissing) {
		t.Fatalf("empty with anchor: %v", err)
	}
	// Mismatching hash at an existing sequence.
	wrong := Checkpoint{Sequence: 2, Hash: cps[3].Hash}
	if _, err := Verify(bytes.NewReader(full), &wrong); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("wrong anchor: %v", err)
	}
	// Malformed anchors.
	for _, a := range []Checkpoint{
		{Sequence: 1, Hash: "xyz"},
		{Sequence: 0, Hash: cps[1].Hash},
		{Sequence: 1, Hash: strings.ToUpper(cps[1].Hash)},
	} {
		a := a
		if _, err := Verify(bytes.NewReader(full), &a); !errors.Is(err, ErrAnchorInvalid) {
			t.Fatalf("anchor %+v: %v", a, err)
		}
	}
}

// FuzzVerifyAnchoredFrame feeds mutated/truncated bytes of the canonical
// one-record fixture to Verify with the trusted sequence-1 anchor. Verify must
// never panic; any success must yield exactly the fixture head and the input
// must begin with the canonical frame (no mutated record is ever accepted).
func FuzzVerifyAnchoredFrame(f *testing.F) {
	frame, head, err := encode(vEvent(1), Genesis())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(frame)
	f.Add(frame[:len(frame)/2])
	f.Add(frame[:len(frame)-1])
	f.Add(append(append([]byte{}, frame...), frame...))
	f.Add(append(append([]byte{}, frame...), 0))
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add(bytes.Repeat([]byte{0}, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4*len(frame)+64 {
			t.Skip()
		}
		anchor := head
		got, err := Verify(bytes.NewReader(data), &anchor)
		if err != nil {
			return
		}
		if got != head {
			t.Fatalf("accepted with wrong head: %+v", got)
		}
		if !bytes.HasPrefix(data, frame) {
			t.Fatalf("accepted input that does not start with the canonical frame (len %d)", len(data))
		}
	})
}

func TestTornTail(t *testing.T) {
	frames, cps := vChain(t, 3)
	prefix := vJoin(frames[:2]...)
	torn := append(append([]byte{}, prefix...), frames[2][:len(frames[2])/2]...)

	head, n, err := scan(bytes.NewReader(torn), nil)
	if !errors.Is(err, ErrTornTail) || head != cps[2] || n != int64(len(prefix)) {
		t.Fatalf("scan = %+v, %d, %v", head, n, err)
	}
	// Anchor reached before the torn tail still permits it.
	if _, n, err := scan(bytes.NewReader(torn), &cps[2]); !errors.Is(err, ErrTornTail) || n != int64(len(prefix)) {
		t.Fatalf("anchored torn: %d, %v", n, err)
	}
	// Anchor beyond the valid prefix: recovery not permitted.
	if _, _, err := scan(bytes.NewReader(torn), &cps[3]); !errors.Is(err, ErrAnchorMissing) || errors.Is(err, ErrTornTail) {
		t.Fatalf("unmatched anchor torn: %v", err)
	}
	// Whole frame minus only the LF is still torn.
	noLF := append(append([]byte{}, prefix...), frames[2][:len(frames[2])-1]...)
	if _, n, err := scan(bytes.NewReader(noLF), nil); !errors.Is(err, ErrTornTail) || n != int64(len(prefix)) {
		t.Fatalf("no-LF tail: %d, %v", n, err)
	}
	// Verify does not accept a torn tail.
	if _, err := Verify(bytes.NewReader(torn), nil); !errors.Is(err, ErrTornTail) {
		t.Fatalf("Verify torn: %v", err)
	}
	// A corrupt complete record before a torn tail is not recoverable.
	bad := append(vJoin(frames[0], bytes.Replace(frames[1], []byte(`"allowed"`), []byte(`"denied"`), 1)), frames[2][:10]...)
	if _, _, err := scan(bytes.NewReader(bad), nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt before torn: %v", err)
	}
}

func TestOversizedNeverRecoverable(t *testing.T) {
	frames, _ := vChain(t, 1)
	for name, tail := range map[string][]byte{
		"oversized unterminated": bytes.Repeat([]byte("a"), maxFrame),
		"huge unterminated":      bytes.Repeat([]byte("a"), 100000),
		"oversized line":         append(bytes.Repeat([]byte("a"), maxFrame), '\n'),
		"huge line":              append(bytes.Repeat([]byte("a"), 100000), '\n'),
	} {
		_, _, err := scan(bytes.NewReader(append(vJoin(frames...), tail...)), nil)
		if !errors.Is(err, ErrOversized) || errors.Is(err, ErrTornTail) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// Just under the bound is torn, not oversized.
	tail := bytes.Repeat([]byte("a"), maxFrame-1)
	if _, _, err := scan(bytes.NewReader(tail), nil); !errors.Is(err, ErrTornTail) {
		t.Fatalf("bounded tail: %v", err)
	}
}

func TestMalformedCompleteRecord(t *testing.T) {
	frames, _ := vChain(t, 2)
	data := vJoin(frames[0], []byte("{\"version\":1}\n"), frames[1])
	_, _, err := scan(bytes.NewReader(data), nil)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "expected sequence 2") {
		t.Fatalf("missing expected sequence: %v", err)
	}
}

func TestErrorsDoNotEchoUntrustedInput(t *testing.T) {
	const secret = "SUPERSECRET-token-9f3a"
	frames, _ := vChain(t, 2)
	hostile := [][]byte{
		[]byte(`{"version":1,"actor_id":"` + secret + `","hash":"` + secret + "\"}\n"),
		[]byte(`{"unknown_` + secret + `":1}` + "\n"),
		[]byte(secret + "\n"),
		[]byte(`{"version":"` + secret + `"}` + "\n"),
		bytes.Replace(frames[1], []byte(`"operator"`), []byte(`"`+secret+`"`), 1),
		bytes.Replace(frames[1], []byte(`"vault_unseal"`), []byte(`"`+secret+`"`), 1),
		bytes.Replace(frames[1], []byte(`"2026-01-02T03:04:05.000000002Z"`), []byte(`"`+secret+`"`), 1),
	}
	for i, h := range hostile {
		data := vJoin(frames[0], h)
		_, err := Verify(bytes.NewReader(data), nil)
		if err == nil {
			t.Fatalf("case %d verified", i)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("case %d echoed payload: %v", i, err)
		}
		// Torn variant (no LF).
		_, _, err = scan(bytes.NewReader(vJoin(frames[0], bytes.TrimSuffix(h, []byte("\n")))), nil)
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("case %d torn echoed payload: %v", i, err)
		}
	}
	// Anchor errors too.
	a := Checkpoint{Sequence: 1, Hash: secret}
	if _, err := Verify(bytes.NewReader(nil), &a); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("anchor error = %v", err)
	}
}

type vFakeLog struct {
	events []Event
	err    error
}

func (f *vFakeLog) Append(e Event) (Checkpoint, error) {
	if f.err != nil {
		return Checkpoint{}, f.err
	}
	f.events = append(f.events, e)
	return Checkpoint{Sequence: uint64(len(f.events))}, nil
}

func vMeta() Meta {
	return Meta{
		At:            time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ActorKind:     ActorClient,
		ActorID:       vID(1),
		IntegrationID: vID(9),
		CorrelationID: vID(0x70),
	}
}

func TestHooksRecordTypedActions(t *testing.T) {
	log := &vFakeLog{}
	h := NewHooks(log)
	steps := []struct {
		call   func(Meta, Outcome) error
		action Action
	}{
		{h.VaultUnseal, ActionVaultUnseal},
		{h.SecretAccess, ActionSecretAccess},
		{h.APIAuth, ActionAPIAuth},
		{h.ClientEnrollment, ActionClientEnrollment},
		{h.ClientConnection, ActionClientConnection},
	}
	for _, s := range steps {
		if err := s.call(vMeta(), OutcomeAllowed); err != nil {
			t.Fatalf("%s: %v", s.action, err)
		}
	}
	if len(log.events) != len(steps) {
		t.Fatalf("events = %d", len(log.events))
	}
	m := vMeta()
	for i, s := range steps {
		e := log.events[i]
		want := Event{At: m.At, ActorKind: m.ActorKind, ActorID: m.ActorID, IntegrationID: m.IntegrationID, Action: s.action, Outcome: OutcomeAllowed, CorrelationID: m.CorrelationID}
		if e != want {
			t.Errorf("event %d = %+v, want %+v", i, e, want)
		}
	}
}

func TestHooksFailClosed(t *testing.T) {
	var zero Hooks
	var nilHooks *Hooks
	var nilLog *vFakeLog
	typedNil := NewHooks(nilLog)
	untyped := NewHooks(nil)
	for name, h := range map[string]*Hooks{"zero": &zero, "nil": nilHooks, "typed nil": &typedNil, "nil log": &untyped} {
		if err := h.VaultUnseal(vMeta(), OutcomeAllowed); !errors.Is(err, ErrHooksUnconfigured) {
			t.Errorf("%s: %v", name, err)
		}
		if err := h.SecretAccess(vMeta(), OutcomeDenied); !errors.Is(err, ErrHooksUnconfigured) {
			t.Errorf("%s secret: %v", name, err)
		}
	}
}

func TestHooksValidationAndErrorPassthrough(t *testing.T) {
	log := &vFakeLog{}
	h := NewHooks(log)

	m := vMeta()
	m.IntegrationID = ID{}
	if err := h.SecretAccess(m, OutcomeAllowed); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("secret without integration: %v", err)
	}
	if err := h.APIAuth(m, OutcomeAllowed); err != nil {
		t.Fatalf("api auth without integration: %v", err)
	}
	m.ActorKind = ActorUnknown
	if err := h.APIAuth(m, OutcomeAllowed); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("unknown actor allowed: %v", err)
	}
	if err := h.APIAuth(m, OutcomeDenied); err != nil {
		t.Fatalf("unknown actor denied: %v", err)
	}
	m = vMeta()
	m.CorrelationID = ID{}
	if err := h.VaultUnseal(m, OutcomeError); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("zero correlation: %v", err)
	}
	n := len(log.events)
	if err := h.VaultUnseal(m, OutcomeAllowed); err == nil || len(log.events) != n {
		t.Fatal("invalid event reached the log")
	}

	sentinel := errors.New("disk full")
	log.err = sentinel
	if err := h.VaultUnseal(vMeta(), OutcomeAllowed); err != sentinel {
		t.Fatalf("append error not returned unchanged: %v", err)
	}
	if err := h.VaultUnseal(vMeta(), OutcomeDenied); err != sentinel {
		t.Fatalf("deny append error not returned unchanged: %v", err)
	}
}

func TestHookEventsRoundTripThroughWire(t *testing.T) {
	// Hostile-looking input can only reach the log as typed fields; the frame
	// contains nothing but enum values, hex IDs and a timestamp.
	var buf bytes.Buffer
	cp := Genesis()
	rec := vRecorder{fn: func(e Event) (Checkpoint, error) {
		f, next, err := encode(e, cp)
		if err != nil {
			return Checkpoint{}, err
		}
		buf.Write(f)
		cp = next
		return next, nil
	}}
	h := NewHooks(rec)
	m := vMeta()
	m.ActorKind = ActorKind(`operator","action":"x`)
	if err := h.APIAuth(m, OutcomeAllowed); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("hostile kind accepted: %v", err)
	}
	m = vMeta()
	if err := h.SecretAccess(m, OutcomeDenied); err != nil {
		t.Fatal(err)
	}
	if err := h.APIAuth(m, Outcome("allowed\n{}")); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("hostile outcome accepted: %v", err)
	}
	head, err := Verify(&buf, nil)
	if err != nil || head != cp || head.Sequence != 1 {
		t.Fatalf("Verify = %+v, %v", head, err)
	}
}

type vRecorder struct {
	fn func(Event) (Checkpoint, error)
}

func (r vRecorder) Append(e Event) (Checkpoint, error) { return r.fn(e) }
