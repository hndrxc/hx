// Package ipc implements the hub's local operator IPC transport.
//
// Platform adapters (Unix socket, Windows named pipe) construct a Listener
// with newListener, supplying an OS-specific peer authorizer. This file holds
// the cross-platform framing, authorization ordering, and lifecycle.
//
// Wire format: each connection carries exactly one request and at most one
// response. A message is a 4-byte big-endian unsigned length N followed by N
// payload bytes, with 1 <= N <= MaxMessageBytes. Any failure (peer denial,
// audit failure, malformed or oversized frame, handler error, deadline) closes
// the connection without a response; the client sees EOF and learns nothing
// further. The payload is never read before the peer is authorized by the OS
// adapter and an allowed APIAuth event is durably recorded.
package ipc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hndrxc/hx/internal/hub/audit"
)

const (
	// MaxMessageBytes bounds request and response payloads.
	MaxMessageBytes = 64 << 10

	// maxConns bounds concurrently served connections; Accept is not called
	// while all slots are busy, so excess peers wait in the OS backlog.
	maxConns = 16
	// connTimeout is the absolute deadline for one connection's exchange.
	connTimeout = 10 * time.Second
)

var (
	// ErrServing is returned when Serve is called more than once.
	ErrServing = errors.New("ipc: listener already serving")
	// ErrClosed is returned by Serve after Close.
	ErrClosed = errors.New("ipc: listener closed")

	errFrame = errors.New("ipc: invalid frame")
)

// Listener serves single-exchange framed requests from authorized local peers.
type Listener struct {
	raw       net.Listener
	authorize func(net.Conn) (audit.ID, error)
	hooks     audit.Hooks
	now       func() time.Time
	timeout   time.Duration

	serving atomic.Bool
	closed  chan struct{}
	once    sync.Once

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	cancel context.CancelFunc // cancels handler contexts; set by Serve
}

// newListener wraps raw. authorize performs OS-specific peer verification and
// returns the peer's opaque, nonzero operator ID. Only platform adapters call it.
func newListener(raw net.Listener, authorize func(net.Conn) (audit.ID, error), hooks audit.Hooks) *Listener {
	return &Listener{
		raw:       raw,
		authorize: authorize,
		hooks:     hooks,
		now:       time.Now,
		timeout:   connTimeout,
		closed:    make(chan struct{}),
		conns:     make(map[net.Conn]struct{}),
	}
}

// Close stops accepting, cancels running handler contexts, closes active
// connections, and makes Serve return once in-flight handlers have returned.
// It does not wait itself and is idempotent.
func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.closed)
		err = l.raw.Close()
		l.mu.Lock()
		if l.cancel != nil {
			l.cancel()
		}
		for c := range l.conns {
			_ = c.Close()
		}
		l.mu.Unlock()
	})
	return err
}

// Serve accepts connections until ctx is cancelled or Close is called, then
// closes the listener and all active connections and waits for in-flight
// handlers to return before returning. handler receives a context cancelled
// on Close, ctx cancellation, or the connection deadline; a non-nil error or
// oversized response closes the connection without a reply.
//
// Cancellation is cooperative: handlers must return promptly once their
// context is done. Serve cannot abandon a handler goroutine, so a handler that
// ignores its context delays Serve's return. The request slice is only valid
// until the response has been written; handlers must not retain it.
func (l *Listener) Serve(ctx context.Context, handler func(context.Context, audit.ID, []byte) ([]byte, error)) error {
	if !l.serving.CompareAndSwap(false, true) {
		return ErrServing
	}
	parent := ctx
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	l.mu.Lock()
	l.cancel = cancel
	select {
	case <-l.closed: // Close ran before Serve: children start cancelled.
		cancel()
	default:
	}
	l.mu.Unlock()
	stop := context.AfterFunc(parent, func() { _ = l.Close() })
	defer stop()

	slots := make(chan struct{}, maxConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer l.Close()

	for {
		select {
		case slots <- struct{}{}:
		case <-l.closed:
			return l.exitErr(parent)
		}
		conn, err := l.raw.Accept()
		if err != nil {
			<-slots
			select {
			case <-l.closed:
				return l.exitErr(parent)
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if !l.track(conn) {
			_ = conn.Close()
			<-slots
			return l.exitErr(parent)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer l.untrack(conn)
			l.serveConn(ctx, conn, handler)
		}()
	}
}

func (l *Listener) exitErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrClosed
}

func (l *Listener) track(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return false
	default:
	}
	l.conns[c] = struct{}{}
	return true
}

func (l *Listener) untrack(c net.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
	_ = c.Close()
}

func (l *Listener) serveConn(ctx context.Context, conn net.Conn, handler func(context.Context, audit.ID, []byte) ([]byte, error)) {
	deadline := l.now().Add(l.timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return
	}
	corr, err := randomID()
	if err != nil {
		return
	}
	actor, err := l.authorize(conn)
	if err != nil || actor.IsZero() {
		// Unattributed denial: a fresh opaque per-attempt actor ID.
		anon, rerr := randomID()
		if rerr == nil {
			_ = l.hooks.APIAuth(l.meta(audit.ActorUnknown, anon, corr), audit.OutcomeDenied)
		}
		return
	}
	if l.hooks.APIAuth(l.meta(audit.ActorOperator, actor, corr), audit.OutcomeAllowed) != nil {
		return
	}
	req, err := readFrame(conn)
	if err != nil {
		_ = l.hooks.APIAuth(l.meta(audit.ActorOperator, actor, corr), audit.OutcomeError)
		return
	}
	// The response may alias req, so zero it only after the write.
	defer clear(req)
	hctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// A buffered read can complete after shutdown or the deadline; never
	// dispatch in that case.
	if hctx.Err() != nil || !l.now().Before(deadline) {
		_ = l.hooks.APIAuth(l.meta(audit.ActorOperator, actor, corr), audit.OutcomeError)
		return
	}
	resp, err := handler(hctx, actor, req)
	if err != nil || hctx.Err() != nil || len(resp) == 0 || len(resp) > MaxMessageBytes {
		_ = l.hooks.APIAuth(l.meta(audit.ActorOperator, actor, corr), audit.OutcomeError)
		return
	}
	_ = writeFrame(conn, resp)
}

func (l *Listener) meta(kind audit.ActorKind, actor, corr audit.ID) audit.Meta {
	return audit.Meta{At: l.now(), ActorKind: kind, ActorID: actor, CorrelationID: corr}
}

func randomID() (audit.ID, error) {
	var id audit.ID
	for id.IsZero() {
		if _, err := rand.Read(id[:]); err != nil {
			return audit.ID{}, err
		}
	}
	return id, nil
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, errFrame
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxMessageBytes {
		return nil, errFrame
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, errFrame
	}
	return buf, nil
}

func writeFrame(w io.Writer, p []byte) error {
	n := len(p)
	if n == 0 || n > MaxMessageBytes {
		return errFrame
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(n))
	if err := writeFull(w, hdr[:]); err != nil {
		return err
	}
	return writeFull(w, p)
}

// writeFull treats a short write without an error as io.ErrShortWrite.
func writeFull(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}
