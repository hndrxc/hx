//go:build linux

package rpc

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/hndrxc/hx/internal/hub/audit"
	"github.com/hndrxc/hx/internal/hub/enroll"
)

// Endpoint test procedures. They are test doubles only; no business RPC.
const (
	endpointReadProc   = "/hx.test.v1.EndpointTest/Read"
	endpointIngestProc = "/hx.test.v1.EndpointTest/Ingest"
	endpointAdminProc  = "/hx.test.v1.EndpointTest/Admin"
	endpointStreamProc = "/hx.test.v1.EndpointTest/Watch"

	endpointSpoofAddr = "127.0.0.1:1"
	endpointWait      = 10 * time.Second
)

var errEndpointUnknownPeer = errors.New("test whois: unknown peer")

// endpointAuditLog appends to a real audit.Log and keeps a copy of events.
type endpointAuditLog struct {
	mu     sync.Mutex
	log    *audit.Log
	events []audit.Event
}

func (r *endpointAuditLog) Append(e audit.Event) (audit.Checkpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp, err := r.log.Append(e)
	if err == nil {
		r.events = append(r.events, e)
	}
	return cp, err
}

func (r *endpointAuditLog) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

// fakeWhoIs is a concurrency-safe stand-in for tsnet LocalClient().WhoIs,
// keyed by the transport remote address.
type fakeWhoIs struct {
	mu    sync.Mutex
	peers map[string]enroll.TailnetPeer
	calls []string
}

func (w *fakeWhoIs) set(addr string, p enroll.TailnetPeer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.peers[addr] = p
}

func (w *fakeWhoIs) whoIs(ctx context.Context, addr string) (enroll.TailnetPeer, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, addr)
	if err := ctx.Err(); err != nil {
		return enroll.TailnetPeer{}, err
	}
	p, ok := w.peers[addr]
	if !ok {
		return enroll.TailnetPeer{}, errEndpointUnknownPeer
	}
	p.Tags = append([]string(nil), p.Tags...)
	return p, nil
}

func (w *fakeWhoIs) called() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.calls...)
}

// endpointGate synchronizes one server-stream handler invocation.
type endpointGate struct {
	proceed chan struct{}
	second  chan error
}

type endpointCall struct {
	proc string
	id   enroll.ID
	ok   bool
}

// endpointHarness wires a real Ed25519 CA, enrollment registry and audit log
// to newServer on a loopback-only TLS listener.
type endpointHarness struct {
	t          *testing.T
	rootDER    []byte
	rootKey    ed25519.PrivateKey
	roots      *x509.CertPool
	serverCert tls.Certificate
	auditPath  string
	audit      *endpointAuditLog
	hooks      audit.Hooks
	svc        *enroll.Service
	operator   enroll.LocalPeer
	who        *fakeWhoIs

	mu    sync.Mutex
	calls []endpointCall
	gates map[string]*endpointGate
}

// endpointCredential is an enrolled client identity plus its key.
type endpointCredential struct {
	ID   enroll.ID
	Cert tls.Certificate
	Peer enroll.TailnetPeer
}

func newEndpointCA(t *testing.T, cn string) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, cert, key
}

func newEndpointLeaf(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "hx endpoint test leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"hub.hx.test"},

		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func newEndpointHarness(t *testing.T) *endpointHarness {
	t.Helper()
	dir := t.TempDir()
	h := &endpointHarness{
		t:         t,
		auditPath: filepath.Join(dir, "audit.log"),
		who:       &fakeWhoIs{peers: map[string]enroll.TailnetPeer{}},
		gates:     map[string]*endpointGate{},
	}
	l, err := audit.Open(h.auditPath, audit.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	h.audit = &endpointAuditLog{log: l}
	h.hooks = audit.NewHooks(h.audit)

	var ca *x509.Certificate
	h.rootDER, ca, h.rootKey = newEndpointCA(t, "hx endpoint test CA")
	h.roots = x509.NewCertPool()
	h.roots.AddCert(ca)
	h.serverCert = newEndpointLeaf(t, ca, h.rootKey, x509.ExtKeyUsageServerAuth)

	caKey := h.rootKey
	authority, err := enroll.NewAuthority(h.rootDER, func(_ context.Context, use func(crypto.Signer) error) error {
		return use(caKey)
	})
	if err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(dir, "registry")
	if err := os.Mkdir(reg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(reg, 0o700); err != nil {
		t.Fatal(err)
	}
	h.svc, err = enroll.Open(reg, authority, h.hooks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.svc.Close() })
	var opID enroll.ID
	opID[0] = 0x0a
	h.operator = enroll.LocalPeer{ID: opID, Operator: true}
	return h
}

func (h *endpointHarness) config(methods []Method) Config {
	return Config{
		TLSCertificate: h.serverCert,
		RootDER:        h.rootDER,
		Enrollment:     h.svc,
		Audit:          h.hooks,
		Methods:        methods,
	}
}

func (h *endpointHarness) recordCall(proc string, id enroll.ID, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, endpointCall{proc: proc, id: id, ok: ok})
}

func (h *endpointHarness) handled() []endpointCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]endpointCall(nil), h.calls...)
}

// gate registers a stream gate addressed by the stream request text.
func (h *endpointHarness) gate(key string) *endpointGate {
	g := &endpointGate{proceed: make(chan struct{}), second: make(chan error, 1)}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.gates[key] = g
	return g
}

func (h *endpointHarness) unaryHandler() connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		var req wrapperspb.StringValue
		if err := stream.Receive(&req); err != nil {
			return err
		}
		id, ok := Caller(ctx)
		h.recordCall(spec.Procedure, id, ok)
		if !ok || id.IsZero() {
			return connect.NewError(connect.CodeInternal, "handler reached without caller")
		}
		return stream.Send(wrapperspb.String(id.String()))
	}
}

// streamHandler emits once, waits for its gate (or ctx), then tries a
// second emission and reports that attempt's error.
func (h *endpointHarness) streamHandler() connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		var req wrapperspb.StringValue
		if err := stream.Receive(&req); err != nil {
			return err
		}
		id, ok := Caller(ctx)
		h.recordCall(spec.Procedure, id, ok)
		if !ok || id.IsZero() {
			return connect.NewError(connect.CodeInternal, "handler reached without caller")
		}
		h.mu.Lock()
		g := h.gates[req.GetValue()]
		h.mu.Unlock()
		if g == nil {
			return connect.NewError(connect.CodeInternal, "unknown gate")
		}
		if err := stream.Send(wrapperspb.String("first")); err != nil {
			g.second <- errors.New("first emission failed")
			return err
		}
		select {
		case <-g.proceed:
		case <-ctx.Done():
		}
		err := stream.Send(wrapperspb.String("second"))
		g.second <- err
		return err
	}
}

func (h *endpointHarness) methods() []Method {
	return []Method{
		{Action: enroll.ActionRead, Method: connect.Method{
			Spec:    connect.Spec{StreamType: connect.StreamTypeUnary, Procedure: endpointReadProc},
			Handler: h.unaryHandler(),
		}},
		{Action: enroll.ActionIngest, Method: connect.Method{
			Spec:    connect.Spec{StreamType: connect.StreamTypeUnary, Procedure: endpointIngestProc},
			Handler: h.unaryHandler(),
		}},
		{Action: enroll.ActionRead, Method: connect.Method{
			Spec:    connect.Spec{StreamType: connect.StreamTypeServer, Procedure: endpointStreamProc},
			Handler: h.streamHandler(),
		}},
	}
}

// serve builds the server with newServer and serves it with real TLS and
// HTTP/2 on an ephemeral loopback port. It returns newServer's error unchanged.
func (h *endpointHarness) serve(t *testing.T, methods []Method) (*http.Server, string, error) {
	t.Helper()
	srv, err := newServer(h.config(methods), h.who.whoIs)
	if err != nil {
		return nil, "", err
	}
	if srv == nil || srv.TLSConfig == nil {
		t.Fatal("newServer returned no TLS server")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(endpointWait):
			t.Error("server did not stop")
		}
	})
	return srv, "https://" + ln.Addr().String(), nil
}

func (h *endpointHarness) start(t *testing.T) (*http.Server, string) {
	t.Helper()
	srv, base, err := h.serve(t, h.methods())
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return srv, base
}

func endpointCSR(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func endpointBinding(name string, role enroll.Role) enroll.Binding {
	tag := "tag:hx-client"
	if role == enroll.RoleIngest {
		tag = "tag:hx-agent"
	}
	return enroll.Binding{NodeID: "node-" + name, UserID: "user-" + name, Tag: tag}
}

// enroll approves and enrolls name through the real registry.
func (h *endpointHarness) enroll(t *testing.T, name string, role enroll.Role) endpointCredential {
	t.Helper()
	b := endpointBinding(name, role)
	peer := enroll.TailnetPeer{NodeID: b.NodeID, UserID: b.UserID, Tags: []string{"tag:other", b.Tag}}
	csr, key := endpointCSR(t)
	tok, err := h.svc.Approve(t.Context(), h.operator, b, role, csr)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	cred, err := h.svc.Enroll(t.Context(), peer, tok, csr)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	leaf, err := x509.ParseCertificate(cred.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	return endpointCredential{
		ID:   cred.ID,
		Cert: tls.Certificate{Certificate: [][]byte{cred.CertificateDER}, PrivateKey: key, Leaf: leaf},
		Peer: peer,
	}
}

// endpointClient dials over TLS itself so every connection's local address
// is mapped in the fake WhoIs before the handshake and h2 is proven.
type endpointClient struct {
	rpc   *connect.Client
	http  *http.Client
	base  string
	dials atomic.Int32
}

// client builds a client presenting cert (nil: none), trusting roots, and
// whose connections WhoIs resolves to peer (nil: unknown peer).
func (h *endpointHarness) client(t *testing.T, base string, cert *tls.Certificate, roots *x509.CertPool, peer *enroll.TailnetPeer) *endpointClient {
	t.Helper()
	cfg := &tls.Config{
		RootCAs:    roots,
		ServerName: "hub.hx.test",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS13,
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	c := &endpointClient{base: base}
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c.dials.Add(1)
			var d net.Dialer
			raw, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if peer != nil {
				h.who.set(raw.LocalAddr().String(), *peer)
			}
			conn := tls.Client(raw, cfg.Clone())
			if err := conn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
				_ = conn.Close()
				return nil, errors.New("negotiated " + p + ", want h2")
			}
			return conn, nil
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	c.http = &http.Client{Transport: tr}
	c.rpc = connect.NewClient(connecthttp.NewTransport(c.http, base))
	return c
}

func (c *endpointClient) unary(ctx context.Context, proc, msg string, header map[string]string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, endpointWait)
	defer cancel()
	ctx, info := connect.NewClientContext(ctx)
	for k, v := range header {
		info.RequestHeader().Set(k, v)
	}
	var res wrapperspb.StringValue
	err := c.rpc.CallUnary(ctx, connect.Spec{StreamType: connect.StreamTypeUnary, Procedure: proc}, wrapperspb.String(msg), &res)
	return res.GetValue(), err
}

func (c *endpointClient) stream(ctx context.Context, key string) (connect.ClientStream, error) {
	return c.rpc.CallServerStream(ctx, connect.Spec{StreamType: connect.StreamTypeServer, Procedure: endpointStreamProc}, wrapperspb.String(key))
}

func (h *endpointHarness) countCalls(proc string) int {
	n := 0
	for _, c := range h.handled() {
		if c.proc == proc {
			n++
		}
	}
	return n
}

func (h *endpointHarness) countEvents(o audit.Outcome) int {
	n := 0
	for _, e := range h.audit.snapshot() {
		if e.Action == audit.ActionAPIAuth && e.Outcome == o {
			n++
		}
	}
	return n
}

// wantAllowed asserts a unary call reached its handler as cred, with an
// allowed api_auth audit event attributed to cred.
func (h *endpointHarness) wantAllowed(t *testing.T, c *endpointClient, proc string, cred endpointCredential, header map[string]string) {
	t.Helper()
	got, err := c.unary(t.Context(), proc, "x", header)
	if err != nil {
		t.Fatalf("%s: %v", proc, err)
	}
	if got != cred.ID.String() {
		t.Fatalf("%s: caller %q, want %s", proc, got, cred.ID)
	}
	for _, e := range h.audit.snapshot() {
		if e.Action == audit.ActionAPIAuth && e.Outcome == audit.OutcomeAllowed &&
			e.ActorKind == audit.ActorClient && e.ActorID == cred.ID {
			return
		}
	}
	t.Fatalf("%s: no allowed api_auth event for %s", proc, cred.ID)
}

// wantDenied asserts the call failed without reaching any handler. When codes
// are given, the failure must carry one of them.
func (h *endpointHarness) wantDenied(t *testing.T, c *endpointClient, proc string, header map[string]string, codes ...connect.Code) {
	t.Helper()
	before := len(h.handled())
	_, err := c.unary(t.Context(), proc, "x", header)
	if err == nil {
		t.Fatalf("%s: allowed, want denial", proc)
	}
	if after := len(h.handled()); after != before {
		t.Fatalf("%s: handler reached on denial", proc)
	}
	if len(codes) == 0 {
		return
	}
	got := connect.CodeOf(err)
	for _, c := range codes {
		if got == c {
			return
		}
	}
	t.Fatalf("%s: code %v (%v), want one of %v", proc, got, err, codes)
}

var endpointAuthCodes = []connect.Code{connect.CodePermissionDenied, connect.CodeUnauthenticated}

func TestEndpointServerLimits(t *testing.T) {
	h := newEndpointHarness(t)
	srv, err := newServer(h.config(h.methods()), h.who.whoIs)
	if err != nil {
		t.Fatal(err)
	}
	if srv.ReadHeaderTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("unbounded timeouts: header %v idle %v", srv.ReadHeaderTimeout, srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Fatal("unbounded header size")
	}
	if srv.HTTP2 == nil || srv.HTTP2.MaxConcurrentStreams <= 0 {
		t.Fatal("unbounded HTTP/2 concurrent streams")
	}
	if c := srv.TLSConfig.ClientAuth; c != tls.RequireAnyClientCert && c != tls.RequireAndVerifyClientCert {
		t.Fatalf("client auth %v, want required client certificate", c)
	}
	if srv.TLSConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("min TLS version %x", srv.TLSConfig.MinVersion)
	}
}

func TestEndpointRejectsInvalidConfig(t *testing.T) {
	h := newEndpointHarness(t)
	for name, mut := range map[string]func(*Config){
		"no enrollment": func(c *Config) { c.Enrollment = nil },
		"no root":       func(c *Config) { c.RootDER = nil },
		"no cert":       func(c *Config) { c.TLSCertificate = tls.Certificate{} },
		"no audit":      func(c *Config) { c.Audit = audit.Hooks{} },
	} {
		cfg := h.config(h.methods())
		mut(&cfg)
		if _, err := newServer(cfg, h.who.whoIs); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := newServer(h.config(h.methods()), nil); err == nil {
		t.Error("nil whoIs accepted")
	}
}

func TestEndpointIdentityMatrix(t *testing.T) {
	h := newEndpointHarness(t)
	_, base := h.start(t)
	reader := h.enroll(t, "reader", enroll.RoleRead)
	agent := h.enroll(t, "agent", enroll.RoleIngest)
	other := h.enroll(t, "other", enroll.RoleRead)

	t.Run("read allowed", func(t *testing.T) {
		h.wantAllowed(t, h.client(t, base, &reader.Cert, h.roots, &reader.Peer), endpointReadProc, reader, nil)
	})
	t.Run("own ingest allowed", func(t *testing.T) {
		h.wantAllowed(t, h.client(t, base, &agent.Cert, h.roots, &agent.Peer), endpointIngestProc, agent, nil)
	})
	t.Run("read role cannot ingest", func(t *testing.T) {
		h.wantDenied(t, h.client(t, base, &reader.Cert, h.roots, &reader.Peer), endpointIngestProc, nil, endpointAuthCodes...)
	})
	t.Run("ingest role cannot read", func(t *testing.T) {
		h.wantDenied(t, h.client(t, base, &agent.Cert, h.roots, &agent.Peer), endpointReadProc, nil, endpointAuthCodes...)
	})
	t.Run("ingest role cannot stream reads", func(t *testing.T) {
		c := h.client(t, base, &agent.Cert, h.roots, &agent.Peer)
		h.gate("ingest-stream")
		before := h.countCalls(endpointStreamProc)
		ctx, cancel := context.WithTimeout(t.Context(), endpointWait)
		defer cancel()
		s, err := c.stream(ctx, "ingest-stream")
		if err == nil {
			var msg wrapperspb.StringValue
			err = s.Receive(&msg)
			_ = s.Close()
		}
		if err == nil || h.countCalls(endpointStreamProc) != before {
			t.Fatalf("stream allowed for ingest role: %v", err)
		}
	})
	t.Run("unknown procedure", func(t *testing.T) {
		h.wantDenied(t, h.client(t, base, &reader.Cert, h.roots, &reader.Peer), "/hx.test.v1.EndpointTest/Missing", nil)
	})

	denied := h.countEvents(audit.OutcomeDenied)
	wrongNode := reader.Peer
	wrongNode.NodeID = "node-evil"
	wrongUser := reader.Peer
	wrongUser.UserID = "user-evil"
	wrongTag := reader.Peer
	wrongTag.Tags = []string{"tag:other", "tag:hx-agent"}
	noTags := reader.Peer
	noTags.Tags = nil

	_, foreignCA, foreignKey := newEndpointCA(t, "foreign CA")
	foreignLeaf := newEndpointLeaf(t, foreignCA, foreignKey, x509.ExtKeyUsageClientAuth)
	foreignRoots := x509.NewCertPool()
	foreignRoots.AddCert(foreignCA)

	for name, c := range map[string]*endpointClient{
		"wrong node":             h.client(t, base, &reader.Cert, h.roots, &wrongNode),
		"wrong user":             h.client(t, base, &reader.Cert, h.roots, &wrongUser),
		"wrong tag":              h.client(t, base, &reader.Cert, h.roots, &wrongTag),
		"no tags":                h.client(t, base, &reader.Cert, h.roots, &noTags),
		"whois failure":          h.client(t, base, &reader.Cert, h.roots, nil),
		"other node's cert":      h.client(t, base, &other.Cert, h.roots, &reader.Peer),
		"cert from foreign CA":   h.client(t, base, &foreignLeaf, h.roots, &reader.Peer),
		"server cert as client":  h.client(t, base, &h.serverCert, h.roots, &reader.Peer),
		"no client cert":         h.client(t, base, nil, h.roots, &reader.Peer),
		"client trusts wrong CA": h.client(t, base, &reader.Cert, foreignRoots, &reader.Peer),
		"client trusts no root":  h.client(t, base, &reader.Cert, x509.NewCertPool(), &reader.Peer),
	} {
		t.Run(name, func(t *testing.T) {
			h.wantDenied(t, c, endpointReadProc, nil)
		})
	}
	if h.countEvents(audit.OutcomeDenied) <= denied {
		t.Error("identity denials were not audited")
	}

	t.Run("audit sanitized and verifiable", func(t *testing.T) {
		raw, err := os.ReadFile(h.auditPath)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{"node-", "user-", "tag:", "127.0.0.1", "evil", "BEGIN"} {
			if strings.Contains(string(raw), s) {
				t.Errorf("audit log contains %q", s)
			}
		}
		f, err := os.Open(h.auditPath)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := audit.Verify(f, nil); err != nil {
			t.Fatalf("verify audit: %v", err)
		}
	})
}

func TestEndpointUsesTransportPeerNotForwardingHeaders(t *testing.T) {
	h := newEndpointHarness(t)
	_, base := h.start(t)
	reader := h.enroll(t, "reader", enroll.RoleRead)
	h.who.set(endpointSpoofAddr, reader.Peer)
	spoof := map[string]string{
		"X-Forwarded-For":         endpointSpoofAddr,
		"X-Real-Ip":               endpointSpoofAddr,
		"Forwarded":               "for=" + endpointSpoofAddr,
		"Tailscale-User-Login":    reader.Peer.UserID,
		"Tailscale-User-Name":     reader.Peer.UserID,
		"X-Tailscale-Node":        reader.Peer.NodeID,
		"X-Forwarded-Client-Cert": "spoofed",
		"X-Ssl-Client-Cert":       "spoofed",
		"X-Hx-Caller":             reader.ID.String(),
	}
	evil := reader.Peer
	evil.NodeID = "node-evil"
	h.wantDenied(t, h.client(t, base, &reader.Cert, h.roots, &evil), endpointReadProc, spoof)
	h.wantAllowed(t, h.client(t, base, &reader.Cert, h.roots, &reader.Peer), endpointReadProc, reader, spoof)

	calls := h.who.called()
	if len(calls) == 0 {
		t.Fatal("WhoIs never consulted")
	}
	for _, addr := range calls {
		if addr == endpointSpoofAddr {
			t.Fatal("WhoIs consulted with a forwarded-header address")
		}
		ap, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil || !ap.IP.IsLoopback() || ap.Port == 0 {
			t.Fatalf("WhoIs consulted with non-transport address %q", addr)
		}
	}
}

func TestEndpointNoUnauthenticatedRoutes(t *testing.T) {
	h := newEndpointHarness(t)
	_, base := h.start(t)
	reader := h.enroll(t, "reader", enroll.RoleRead)
	anon := h.client(t, base, nil, h.roots, &reader.Peer)
	unknown := h.client(t, base, &reader.Cert, h.roots, nil)
	for _, path := range []string{"/", "/health", "/healthz", "/readyz", "/livez", "/metrics", "/debug/pprof/", "/grpc.health.v1.Health/Check"} {
		for name, c := range map[string]*endpointClient{"no cert": anon, "unknown peer": unknown} {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				ctx, cancel := context.WithTimeout(t.Context(), endpointWait)
				req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				res, err := c.http.Do(req)
				if err == nil {
					body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<10))
					_ = res.Body.Close()
					if res.StatusCode < 400 {
						t.Errorf("%s %s %s: status %d body %q", name, method, path, res.StatusCode, body)
					}
				}
				cancel()
			}
		}
	}
	if len(h.handled()) != 0 {
		t.Fatal("handler reached without authentication")
	}
}

func TestEndpointAdminUnavailableRemotely(t *testing.T) {
	h := newEndpointHarness(t)
	methods := append(h.methods(), Method{Action: enroll.ActionAdmin, Method: connect.Method{
		Spec:    connect.Spec{StreamType: connect.StreamTypeUnary, Procedure: endpointAdminProc},
		Handler: h.unaryHandler(),
	}})
	_, base, err := h.serve(t, methods)
	if err != nil {
		return // refusing to expose admin remotely is acceptable
	}
	reader := h.enroll(t, "reader", enroll.RoleRead)
	agent := h.enroll(t, "agent", enroll.RoleIngest)
	h.wantDenied(t, h.client(t, base, &reader.Cert, h.roots, &reader.Peer), endpointAdminProc, nil, endpointAuthCodes...)
	h.wantDenied(t, h.client(t, base, &agent.Cert, h.roots, &agent.Peer), endpointAdminProc, nil, endpointAuthCodes...)
}

func TestEndpointRejectsUnknownAction(t *testing.T) {
	h := newEndpointHarness(t)
	methods := append(h.methods(), Method{Action: enroll.Action(0), Method: connect.Method{
		Spec:    connect.Spec{StreamType: connect.StreamTypeUnary, Procedure: endpointAdminProc},
		Handler: h.unaryHandler(),
	}})
	if _, err := newServer(h.config(methods), h.who.whoIs); err == nil {
		t.Fatal("method without action accepted")
	}
}

func TestEndpointRevocationClosesExistingAccess(t *testing.T) {
	h := newEndpointHarness(t)
	_, base := h.start(t)
	reader := h.enroll(t, "reader", enroll.RoleRead)
	other := h.enroll(t, "other", enroll.RoleRead)
	c := h.client(t, base, &reader.Cert, h.roots, &reader.Peer)
	h.wantAllowed(t, c, endpointReadProc, reader, nil)
	h.wantAllowed(t, c, endpointReadProc, reader, nil)
	if n := c.dials.Load(); n != 1 {
		t.Fatalf("dials before revocation %d, want 1 reused connection", n)
	}

	if err := h.svc.Revoke(t.Context(), h.operator, reader.ID); err != nil {
		t.Fatal(err)
	}
	h.wantDenied(t, c, endpointReadProc, nil)
	c.http.CloseIdleConnections()
	h.wantDenied(t, c, endpointReadProc, nil)
	h.wantDenied(t, h.client(t, base, &reader.Cert, h.roots, &reader.Peer), endpointReadProc, nil)
	h.wantAllowed(t, h.client(t, base, &other.Cert, h.roots, &other.Peer), endpointReadProc, other, nil)
}

func TestEndpointRevocationStopsEstablishedStream(t *testing.T) {
	h := newEndpointHarness(t)
	_, base := h.start(t)
	reader := h.enroll(t, "reader", enroll.RoleRead)
	c := h.client(t, base, &reader.Cert, h.roots, &reader.Peer)
	g := h.gate("revoke")
	ctx, cancel := context.WithTimeout(t.Context(), endpointWait)
	defer cancel()
	s, err := c.stream(ctx, "revoke")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var msg wrapperspb.StringValue
	if err := s.Receive(&msg); err != nil || msg.GetValue() != "first" {
		t.Fatalf("first emission: %q %v", msg.GetValue(), err)
	}
	if err := h.svc.Revoke(t.Context(), h.operator, reader.ID); err != nil {
		t.Fatal(err)
	}
	close(g.proceed)
	select {
	case err := <-g.second:
		if err == nil {
			t.Fatal("emission after revocation succeeded")
		}
	case <-time.After(endpointWait):
		t.Fatal("handler did not attempt second emission")
	}
	msg.Reset()
	if err := s.Receive(&msg); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("stream continued after revocation: %q %v", msg.GetValue(), err)
	}
	if msg.GetValue() == "second" {
		t.Fatal("second emission delivered after revocation")
	}
}

func TestEndpointDeadlineCancelsStream(t *testing.T) {
	h := newEndpointHarness(t)
	_, base := h.start(t)
	reader := h.enroll(t, "reader", enroll.RoleRead)
	c := h.client(t, base, &reader.Cert, h.roots, &reader.Peer)
	g := h.gate("deadline")
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	s, err := c.stream(ctx, "deadline")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var msg wrapperspb.StringValue
	if err := s.Receive(&msg); err != nil {
		t.Fatalf("first emission: %v", err)
	}
	if err := s.Receive(&msg); connect.CodeOf(err) != connect.CodeDeadlineExceeded && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked stream returned %v, want deadline exceeded", err)
	}
	select {
	case <-g.second:
	case <-time.After(endpointWait):
		t.Fatal("handler context not canceled by client deadline")
	}
}

func TestEndpointConcurrentCalls(t *testing.T) {
	h := newEndpointHarness(t)
	_, base := h.start(t)
	reader := h.enroll(t, "reader", enroll.RoleRead)
	agent := h.enroll(t, "agent", enroll.RoleIngest)
	rc := h.client(t, base, &reader.Cert, h.roots, &reader.Peer)
	ac := h.client(t, base, &agent.Cert, h.roots, &agent.Peer)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			c, proc, want, deny := rc, endpointReadProc, reader.ID, endpointIngestProc
			if i%2 == 1 {
				c, proc, want, deny = ac, endpointIngestProc, agent.ID, endpointReadProc
			}
			got, err := c.unary(t.Context(), proc, "x", nil)
			if err != nil || got != want.String() {
				t.Errorf("%s: %q %v", proc, got, err)
			}
			if _, err := c.unary(t.Context(), deny, "x", nil); err == nil {
				t.Errorf("%s allowed concurrently for wrong role", deny)
			}
		})
	}
	wg.Wait()
	for _, call := range h.handled() {
		want := reader.ID
		if call.proc == endpointIngestProc {
			want = agent.ID
		}
		if !call.ok || call.id != want {
			t.Fatalf("%s handled as %s", call.proc, call.id)
		}
	}
}

func TestEndpointRejectsOversizedMessage(t *testing.T) {
	h := newEndpointHarness(t)
	_, base := h.start(t)
	reader := h.enroll(t, "reader", enroll.RoleRead)
	c := h.client(t, base, &reader.Cert, h.roots, &reader.Peer)
	// One message just above the per-message limit but well under the
	// aggregate body limit must be rejected by Connect's read limit.
	_, err := c.unary(t.Context(), endpointReadProc, strings.Repeat("a", maxMessageBytes+1), nil)
	if code := connect.CodeOf(err); code != connect.CodeResourceExhausted {
		t.Fatalf("oversized message: code %v (%v), want resource_exhausted", code, err)
	}
	if h.countCalls(endpointReadProc) != 0 {
		t.Fatal("oversized message reached handler")
	}

	// A body above the aggregate limit is refused with a generic HTTP 413
	// before Connect, on an otherwise authenticated client.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+endpointReadProc, strings.NewReader(strings.Repeat("a", 5<<20)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/proto")
	res, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status %d, want 413", res.StatusCode)
	}
	if got := strings.TrimSpace(string(body)); got != "request too large" {
		t.Fatalf("oversized body response %q, want generic", got)
	}
	if h.countCalls(endpointReadProc) != 0 {
		t.Fatal("oversized body reached handler")
	}
	h.wantAllowed(t, c, endpointReadProc, reader, nil)
}
