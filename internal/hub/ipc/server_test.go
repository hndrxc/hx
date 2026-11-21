package ipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hndrxc/hx/internal/hub/audit"
)

type pipeListener struct {
	ch        chan net.Conn
	closed    chan struct{}
	once      sync.Once
	ready     chan struct{} // closed on the first Accept call
	readyOnce sync.Once
	accepts   atomic.Int32
}

func newPipeListener() *pipeListener {
	return &pipeListener{ch: make(chan net.Conn), closed: make(chan struct{}), ready: make(chan struct{})}
}

func (p *pipeListener) Accept() (net.Conn, error) {
	p.accepts.Add(1)
	p.readyOnce.Do(func() { close(p.ready) })
	select {
	case c := <-p.ch:
		return c, nil
	case <-p.closed:
		return nil, net.ErrClosed
	}
}

// waitReady blocks until Serve has entered Accept.
func (p *pipeListener) waitReady(t *testing.T) {
	t.Helper()
	waitFor(t, p.ready, "Accept")
}

func (p *pipeListener) Close() error   { p.once.Do(func() { close(p.closed) }); return nil }
func (p *pipeListener) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// dial hands the server end to Accept and returns the client end.
func (p *pipeListener) dial(t *testing.T) net.Conn {
	t.Helper()
	c, s := net.Pipe()
	select {
	case p.ch <- s:
	case <-time.After(2 * time.Second):
		t.Fatal("accept timed out")
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type recLog struct {
	mu     sync.Mutex
	events []audit.Event
	fail   bool
}

func (r *recLog) Append(e audit.Event) (audit.Checkpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return audit.Checkpoint{}, errors.New("disk full")
	}
	r.events = append(r.events, e)
	return audit.Checkpoint{}, nil
}

func (r *recLog) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

var operator = audit.ID{1, 2, 3}

func allow(net.Conn) (audit.ID, error) { return operator, nil }

type harness struct {
	pl     *pipeListener
	log    *recLog
	calls  atomic.Int32
	cancel context.CancelFunc
	done   chan error
}

func start(t *testing.T, authorize func(net.Conn) (audit.ID, error), log *recLog, h func(context.Context, audit.ID, []byte) ([]byte, error)) *harness {
	t.Helper()
	hs := &harness{pl: newPipeListener(), log: log, done: make(chan error, 1)}
	l := newListener(hs.pl, authorize, audit.NewHooks(log))
	l.timeout = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	hs.cancel = cancel
	go func() {
		hs.done <- l.Serve(ctx, func(ctx context.Context, id audit.ID, b []byte) ([]byte, error) {
			hs.calls.Add(1)
			return h(ctx, id, b)
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-hs.done:
		case <-time.After(3 * time.Second):
			t.Error("Serve did not return")
		}
	})
	return hs
}

func echo(_ context.Context, _ audit.ID, b []byte) ([]byte, error) { return b, nil }

func frame(p []byte) []byte {
	b := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(b, uint32(len(p)))
	copy(b[4:], p)
	return b
}

// expectClosed asserts the server closes without a response.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF without response, got n=%d err=%v", n, err)
	}
}

func writeAsync(c net.Conn, b []byte) {
	go func() { _, _ = c.Write(b) }()
}

func TestRoundTrip(t *testing.T) {
	log := &recLog{}
	hs := start(t, allow, log, echo)
	c := hs.pl.dial(t)
	writeAsync(c, frame([]byte("ping")))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := readFrame(c)
	if err != nil || string(got) != "ping" {
		t.Fatalf("got %q, %v", got, err)
	}
	ev := log.snapshot()
	if len(ev) != 1 || ev[0].Outcome != audit.OutcomeAllowed || ev[0].ActorID != operator ||
		ev[0].Action != audit.ActionAPIAuth || ev[0].CorrelationID.IsZero() {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestMalformedFramesNeverReachHandler(t *testing.T) {
	cases := map[string][]byte{
		"zero length": {0, 0, 0, 0},
		"oversized":   binary.BigEndian.AppendUint32(nil, MaxMessageBytes+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			log := &recLog{}
			hs := start(t, allow, log, echo)
			c := hs.pl.dial(t)
			writeAsync(c, raw)
			expectClosed(t, c)
			if hs.calls.Load() != 0 {
				t.Fatal("handler invoked for malformed frame")
			}
		})
	}
}

// Truncated frames are rejected at EOF; an in-memory reader gives a
// deterministic EOF instead of waiting on the server's connection deadline.
func TestReadFrameTruncated(t *testing.T) {
	cases := map[string][]byte{
		"short body":   append(binary.BigEndian.AppendUint32(nil, 10), 'x'),
		"short header": {0, 0},
		"empty":        {},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := readFrame(bytes.NewReader(raw)); !errors.Is(err, errFrame) || got != nil {
				t.Fatalf("readFrame = %q, %v; want errFrame", got, err)
			}
		})
	}
}

func TestOversizedResponseDropped(t *testing.T) {
	hs := start(t, allow, &recLog{}, func(context.Context, audit.ID, []byte) ([]byte, error) {
		return make([]byte, MaxMessageBytes+1), nil
	})
	c := hs.pl.dial(t)
	writeAsync(c, frame([]byte("x")))
	expectClosed(t, c)
}

func TestDeniedPeerAuditedAndNoHandler(t *testing.T) {
	log := &recLog{}
	hs := start(t, func(net.Conn) (audit.ID, error) { return audit.ID{}, errors.New("wrong uid") }, log, echo)
	c := hs.pl.dial(t)
	expectClosed(t, c)
	if hs.calls.Load() != 0 {
		t.Fatal("handler invoked for denied peer")
	}
	ev := log.snapshot()
	if len(ev) != 1 || ev[0].Outcome != audit.OutcomeDenied || ev[0].ActorKind != audit.ActorUnknown ||
		ev[0].ActorID.IsZero() || ev[0].ActorID == operator || ev[0].CorrelationID.IsZero() {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestZeroActorDenied(t *testing.T) {
	hs := start(t, func(net.Conn) (audit.ID, error) { return audit.ID{}, nil }, &recLog{}, echo)
	expectClosed(t, hs.pl.dial(t))
	if hs.calls.Load() != 0 {
		t.Fatal("handler invoked for zero actor")
	}
}

func TestAuditFailureBlocksHandler(t *testing.T) {
	hs := start(t, allow, &recLog{fail: true}, echo)
	c := hs.pl.dial(t)
	expectClosed(t, c)
	if hs.calls.Load() != 0 {
		t.Fatal("handler invoked without durable audit")
	}
}

func TestCancellationClosesActiveAndReturns(t *testing.T) {
	entered := make(chan struct{})
	hs := start(t, allow, &recLog{}, func(ctx context.Context, _ audit.ID, _ []byte) ([]byte, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	c := hs.pl.dial(t)
	writeAsync(c, frame([]byte("x")))
	waitFor(t, entered, "handler")
	hs.cancel()
	select {
	case err := <-hs.done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve = %v", err)
		}
		hs.done <- err
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	expectClosed(t, c)
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func waitServe(t *testing.T, done <-chan error, want error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("Serve = %v, want %v", err, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestConcurrencyBounded(t *testing.T) {
	var active, peak atomic.Int32
	release := make(chan struct{})
	var releaseOnce sync.Once
	full := make(chan struct{})
	hs := start(t, allow, &recLog{}, func(context.Context, audit.ID, []byte) ([]byte, error) {
		n := active.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		if n == maxConns {
			close(full)
		}
		<-release
		active.Add(-1)
		return []byte("ok"), nil
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	for range maxConns {
		c := hs.pl.dial(t)
		writeAsync(c, frame([]byte("x")))
	}
	waitFor(t, full, "all slots busy")
	// Serve acquires a slot before calling Accept, so with every slot held
	// no further Accept call can have been made.
	if n := hs.pl.accepts.Load(); n != maxConns {
		t.Fatalf("Accept called %d times with %d slots busy", n, maxConns)
	}
	releaseOnce.Do(func() { close(release) })
	if p := peak.Load(); p > maxConns {
		t.Fatalf("peak %d > %d", p, maxConns)
	}
}

func TestCloseCancelsHandler(t *testing.T) {
	pl := newPipeListener()
	l := newListener(pl, allow, audit.NewHooks(&recLog{}))
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- l.Serve(context.Background(), func(ctx context.Context, _ audit.ID, _ []byte) ([]byte, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}()
	c := pl.dial(t)
	writeAsync(c, frame([]byte("x")))
	waitFor(t, entered, "handler")
	_ = l.Close()
	waitServe(t, done, ErrClosed)
	expectClosed(t, c)
}

type shortWriter struct{ n int }

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > w.n {
		return w.n, nil
	}
	return len(b), nil
}

func TestWriteFrameShortWrite(t *testing.T) {
	if err := writeFrame(&shortWriter{n: 2}, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("header short write = %v", err)
	}
	if err := writeFrame(&shortWriter{n: 4}, []byte("xyz12")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("payload short write = %v", err)
	}
}

func TestServeTwice(t *testing.T) {
	pl := newPipeListener()
	l := newListener(pl, allow, audit.NewHooks(&recLog{}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Serve(ctx, echo) }()
	pl.waitReady(t)
	if err := l.Serve(ctx, echo); !errors.Is(err, ErrServing) {
		t.Fatalf("second Serve = %v", err)
	}
	cancel()
	waitServe(t, done, context.Canceled)
}

func TestCloseStopsServe(t *testing.T) {
	pl := newPipeListener()
	l := newListener(pl, allow, audit.NewHooks(&recLog{}))
	done := make(chan error, 1)
	go func() { done <- l.Serve(context.Background(), echo) }()
	pl.waitReady(t)
	_ = l.Close()
	waitServe(t, done, ErrClosed)
}
