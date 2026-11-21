//go:build linux

package rpc

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/hndrxc/hx/internal/hub/enroll"
)

const identityURNPrefix = "urn:hx:identity:"

var errRevoked = connect.NewError(connect.CodePermissionDenied, "permission denied")

var errStreamLimit = connect.NewError(connect.CodeResourceExhausted, "stream limit reached")

type guardKey struct{}

// guard is the authorization state of one admitted RPC. Identity comes only
// from the verified TLS chain and WhoIs of the transport remote address.
type guard struct {
	enroll     *enroll.Service
	whoIs      whoIsFunc
	remoteAddr string
	leaf       []byte
	action     enroll.Action
	target     enroll.ID
	cancel     context.CancelFunc
	deny       func()

	mu     sync.Mutex
	id     enroll.ID
	failed bool
	// ops counts stream data operations; bounded by maxStreamOps.
	ops int
}

func withGuard(ctx context.Context, g *guard) context.Context {
	return context.WithValue(ctx, guardKey{}, g)
}

// Caller returns the enrolled caller ID of an admitted RPC. Handlers take
// identity only from here, never from the request.
func Caller(ctx context.Context) (enroll.ID, bool) {
	g, ok := ctx.Value(guardKey{}).(*guard)
	if !ok || g == nil {
		return enroll.ID{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.id.IsZero() {
		return enroll.ID{}, false
	}
	return g.id, true
}

// authorize performs a fresh WhoIs and enrollment authorization. Any
// failure, or a changed caller, permanently fails the guard and cancels the
// RPC.
func (g *guard) authorize(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.authorizeLocked(ctx)
}

func (g *guard) authorizeLocked(ctx context.Context) error {
	if g.failed {
		return enroll.ErrDenied
	}
	err := g.reauthorize(ctx)
	if err != nil {
		g.failed = true
		g.cancel()
		return err
	}
	return nil
}

func (g *guard) reauthorize(ctx context.Context) error {
	wctx, cancel := context.WithTimeout(ctx, whoIsTimeout)
	peer, err := g.whoIs(wctx, g.remoteAddr)
	cancel()
	if err != nil {
		g.deny()
		return enroll.ErrDenied
	}
	id, err := g.enroll.AuthorizeRemote(ctx, peer, g.leaf, g.action, g.target)
	if err != nil {
		return err
	}
	if id.IsZero() || (!g.id.IsZero() && id != g.id) {
		return enroll.ErrDenied
	}
	g.id = id
	return nil
}

// live reports whether the single grant of this RPC still stands, without
// re-authorizing. Unary RPCs use it so the gate's grant is the only one.
func (g *guard) live() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed {
		return errRevoked
	}
	return nil
}

// check performs a fresh WhoIs and durable authorization for one stream
// data operation; nothing is cached between operations. Each stream may
// perform at most maxStreamOps such operations.
func (g *guard) check(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed {
		return errRevoked
	}
	g.ops++
	if g.ops > maxStreamOps {
		g.failed = true
		g.cancel()
		return errStreamLimit
	}
	if g.authorizeLocked(ctx) != nil {
		return errRevoked
	}
	return nil
}

// recheck is the idle watchdog's fresh authorization; it does not count
// against maxStreamOps.
func (g *guard) recheck(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.authorizeLocked(ctx) != nil {
		return errRevoked
	}
	return nil
}

// watch re-authorizes an idle stream every streamRecheckInterval and cancels
// it on failure. Cancellation ends the RPC context; a blocked HTTP/2 body
// read may still last until the hard read deadline. It exits when ctx ends.
func (g *guard) watch(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	t := time.NewTicker(streamRecheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if g.recheck(ctx) != nil {
				return
			}
		}
	}
}

// guardInterceptor refuses any call that did not pass the gate. Unary calls
// keep the gate's single grant; streams are wrapped so every data operation
// is freshly re-authorized.
func guardInterceptor(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		g, ok := ctx.Value(guardKey{}).(*guard)
		if !ok || g == nil {
			return errRevoked
		}
		if err := g.live(); err != nil {
			return err
		}
		if spec.StreamType == connect.StreamTypeUnary {
			return next(ctx, spec, stream)
		}
		return next(ctx, spec, &guardedStream{ctx: ctx, g: g, next: stream})
	}
}

type guardedStream struct {
	ctx  context.Context
	g    *guard
	next connect.ServerStream
}

// Receive authorizes at the delivery boundary: the message is handed to the
// handler only after a fresh grant following its arrival.
func (s *guardedStream) Receive(msg any) error {
	if err := s.g.live(); err != nil {
		return err
	}
	if err := s.next.Receive(msg); err != nil {
		return err
	}
	return s.g.check(s.ctx)
}

func (s *guardedStream) SendHeaders() error {
	if err := s.g.check(s.ctx); err != nil {
		return err
	}
	return s.next.SendHeaders()
}

func (s *guardedStream) Send(msg any) error {
	if err := s.g.check(s.ctx); err != nil {
		return err
	}
	return s.next.Send(msg)
}

// verifiedLeaf returns the leaf of the first chain verified by crypto/tls.
func verifiedLeaf(cs *tls.ConnectionState) (*x509.Certificate, bool) {
	if cs == nil {
		return nil, false
	}
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 || cs.VerifiedChains[0][0] == nil {
		return nil, false
	}
	return cs.VerifiedChains[0][0], true
}

// leafID extracts the signed identity URI of an enrollment leaf. It is a
// routing hint only; enroll.Service re-verifies the leaf on every call.
func leafID(c *x509.Certificate) (enroll.ID, bool) {
	if c == nil || len(c.URIs) != 1 || c.URIs[0] == nil {
		return enroll.ID{}, false
	}
	s := c.URIs[0].String()
	h, ok := strings.CutPrefix(s, identityURNPrefix)
	var id enroll.ID
	if !ok || len(h) != hex.EncodedLen(len(id)) || strings.ToLower(h) != h {
		return enroll.ID{}, false
	}
	if _, err := hex.Decode(id[:], []byte(h)); err != nil || id.IsZero() {
		return enroll.ID{}, false
	}
	return id, true
}

func randomID() (enroll.ID, bool) {
	var id enroll.ID
	if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
		return enroll.ID{}, false
	}
	return id, true
}
