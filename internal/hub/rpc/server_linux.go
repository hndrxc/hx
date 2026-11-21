//go:build linux

// Package rpc is the hub's remote Connect RPC transport. Every route served by
// the returned *http.Server passes the mTLS, WhoIs and enrollment gate; there
// is no unauthenticated route, health route or administrative route.
package rpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/hndrxc/hx/internal/hub/audit"
	"github.com/hndrxc/hx/internal/hub/enroll"
)

// Fixed transport limits. They are not configurable.
const (
	// maxMessageBytes bounds each Connect message received or sent, after
	// decompression.
	maxMessageBytes = 256 << 10
	// maxRequestBodyBytes bounds the aggregate request body of one RPC.
	maxRequestBodyBytes = 4 << 20
	// maxHeaderBytes bounds request headers (HTTP/1.1 and HTTP/2).
	maxHeaderBytes = 16 << 10
	// maxConcurrentRequests caps in-flight RPCs across all connections.
	maxConcurrentRequests = 64
	// maxConcurrentStreams caps HTTP/2 streams per connection.
	maxConcurrentStreams = 16
	// maxProcedureBytes bounds a registered procedure path.
	maxProcedureBytes = 256

	// unaryRequestTimeout is the hard lifetime of a unary RPC.
	unaryRequestTimeout = 30 * time.Second
	// streamRequestTimeout is the hard lifetime of a streaming RPC,
	// idle or not.
	streamRequestTimeout = 5 * time.Minute
	// streamRecheckInterval is the idle watchdog period; data operations
	// are re-authorized individually and never use a cached grant.
	streamRecheckInterval = time.Second
	// maxStreamOps bounds the fresh authorizations (sends, header sends and
	// delivered receives) one streaming RPC may trigger.
	maxStreamOps = 1024
	// whoIsTimeout bounds one WhoIs lookup.
	whoIsTimeout = 5 * time.Second

	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 60 * time.Second
)

// errHandshakeDenied is the fixed handshake rejection; its text is matched by
// the sanitized error log to avoid auditing the same denial twice.
var errHandshakeDenied = errors.New("hx-rpc: handshake denied")

var errConfig = errors.New("rpc: invalid configuration")

// Config is the remote RPC server configuration.
type Config struct {
	// TLSCertificate is the hub server leaf (single certificate, issued
	// directly by RootDER) and its private key.
	TLSCertificate tls.Certificate
	// RootDER is the dedicated hub CA root that client leaves chain to.
	RootDER []byte
	// Enrollment authorizes every call and stream re-check.
	Enrollment *enroll.Service
	// Audit records handshake decisions and gate denials.
	Audit audit.Hooks
	// Methods are the only procedures served.
	Methods []Method
}

// Method is a Connect method with the single action it requires.
type Method struct {
	// Action is enroll.ActionRead or enroll.ActionIngest.
	Action enroll.Action
	Method connect.Method
}

type whoIsFunc func(context.Context, string) (enroll.TailnetPeer, error)

type route struct {
	action  enroll.Action
	timeout time.Duration
	stream  bool
}

type gate struct {
	enroll *enroll.Service
	whoIs  whoIsFunc
	audit  audit.Hooks
	routes map[string]route
	slots  chan struct{}
	next   http.Handler
}

// newServer validates cfg and returns a server ready for
// ServeTLS(listener, "", ""), which enables HTTP/2.
func newServer(cfg Config, whoIs whoIsFunc) (*http.Server, error) {
	if cfg.Enrollment == nil || whoIs == nil || len(cfg.Methods) == 0 || cfg.Audit == (audit.Hooks{}) {
		return nil, errConfig
	}
	now := time.Now()
	root, err := parseRoot(cfg.RootDER, now)
	if err != nil {
		return nil, err
	}
	cert, err := checkServerCertificate(cfg.TLSCertificate, root, now)
	if err != nil {
		return nil, err
	}

	g := &gate{
		enroll: cfg.Enrollment,
		whoIs:  whoIs,
		audit:  cfg.Audit,
		routes: make(map[string]route, len(cfg.Methods)),
		slots:  make(chan struct{}, maxConcurrentRequests),
	}
	cs := connect.NewServer(guardInterceptor)
	for _, m := range cfg.Methods {
		if m.Action != enroll.ActionRead && m.Action != enroll.ActionIngest {
			return nil, errConfig
		}
		spec := m.Method.Spec
		if m.Method.Handler == nil || !validProcedure(spec.Procedure) || !validStreamType(spec.StreamType) {
			return nil, errConfig
		}
		if _, dup := g.routes[spec.Procedure]; dup {
			return nil, errConfig
		}
		r := route{action: m.Action, timeout: unaryRequestTimeout}
		if spec.StreamType != connect.StreamTypeUnary {
			r.timeout, r.stream = streamRequestTimeout, true
		}
		g.routes[spec.Procedure] = r
		cs.Register(m.Method)
	}
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs,
		connecthttp.WithReadMaxBytes(maxMessageBytes),
		connecthttp.WithSendMaxBytes(maxMessageBytes),
	)
	g.next = mux

	pool := x509.NewCertPool()
	pool.AddCert(root)
	h := &handshakeAudit{audit: cfg.Audit}
	tlsConfig := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              pool,
		SessionTicketsDisabled: true,
		VerifyConnection:       h.verify,
	}
	return &http.Server{
		Handler:           g,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       streamRequestTimeout,
		WriteTimeout:      streamRequestTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          log.New(h, "", 0),
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: maxConcurrentStreams,
		},
	}, nil
}

// ServeHTTP admits a request only for an exact registered procedure, a
// verified client chain, the transport WhoIs and a granted enrollment
// authorization; it then applies the fixed limits and deadlines.
func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	rt, ok := g.routes[r.URL.Path]
	if !ok || r.URL.RawQuery != "" {
		g.denyUnknown()
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		g.denyUnknown()
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.ContentLength > maxRequestBodyBytes {
		g.denyUnknown()
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	leaf, ok := verifiedLeaf(r.TLS)
	if !ok {
		g.denyUnknown()
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}
	var target enroll.ID
	if rt.action == enroll.ActionIngest {
		if target, ok = leafID(leaf); !ok {
			g.denyUnknown()
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
	}

	deadline := time.Now().Add(rt.timeout)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	gd := &guard{
		enroll:     g.enroll,
		whoIs:      g.whoIs,
		remoteAddr: r.RemoteAddr,
		leaf:       leaf.Raw,
		action:     rt.action,
		target:     target,
		cancel:     cancel,
		deny:       g.denyUnknown,
	}
	if err := gd.authorize(ctx); err != nil {
		if errors.Is(err, enroll.ErrUnavailable) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}

	rc := http.NewResponseController(w)
	if rc.SetReadDeadline(deadline) != nil || rc.SetWriteDeadline(deadline) != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if rt.stream {
		done := make(chan struct{})
		defer func() { cancel(); <-done }()
		go gd.watch(ctx, done)
	}
	g.next.ServeHTTP(w, r.WithContext(withGuard(ctx, gd)))
}

// denyUnknown records a best-effort denial for an unattributed request.
func (g *gate) denyUnknown() {
	recordUnknown(g.audit.APIAuth)
}

func recordUnknown(h func(audit.Meta, audit.Outcome) error) {
	if id, ok := randomID(); ok {
		_ = h(audit.Meta{At: time.Now(), ActorKind: audit.ActorUnknown, ActorID: id, CorrelationID: id}, audit.OutcomeDenied)
	}
}

// handshakeAudit audits TLS handshakes and is the server's only error log
// sink. It never emits raw parser errors, addresses or certificates.
type handshakeAudit struct {
	audit audit.Hooks
}

// verify runs after crypto/tls verified the client chain against the
// dedicated root. Success is granted only once it is audited.
func (h *handshakeAudit) verify(cs tls.ConnectionState) error {
	now := time.Now()
	leaf, ok := verifiedLeaf(&cs)
	if !ok {
		recordUnknown(h.audit.ClientConnection)
		return errHandshakeDenied
	}
	id, ok := leafID(leaf)
	if !ok {
		recordUnknown(h.audit.ClientConnection)
		return errHandshakeDenied
	}
	corr, ok := randomID()
	if !ok {
		return errHandshakeDenied
	}
	m := audit.Meta{At: now, ActorKind: audit.ActorClient, ActorID: id, CorrelationID: corr}
	if h.audit.ClientConnection(m, audit.OutcomeAllowed) != nil {
		return errHandshakeDenied
	}
	return nil
}

// Write receives http.Server error log lines and replaces them with fixed
// messages.
func (h *handshakeAudit) Write(p []byte) (int, error) {
	switch {
	case bytes.Contains(p, []byte(errHandshakeDenied.Error())):
		slog.Warn("rpc: tls handshake denied")
	case bytes.Contains(p, []byte("TLS handshake error")):
		recordUnknown(h.audit.ClientConnection)
		slog.Warn("rpc: tls handshake rejected")
	default:
		slog.Warn("rpc: server error")
	}
	return len(p), nil
}

func parseRoot(der []byte, now time.Time) (*x509.Certificate, error) {
	root, err := x509.ParseCertificate(der)
	if err != nil || !bytes.Equal(root.Raw, der) {
		return nil, errConfig
	}
	if !root.BasicConstraintsValid || !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 ||
		root.PublicKeyAlgorithm != x509.Ed25519 || !bytes.Equal(root.RawIssuer, root.RawSubject) ||
		root.CheckSignatureFrom(root) != nil || now.Before(root.NotBefore) || now.After(root.NotAfter) {
		return nil, errConfig
	}
	return root, nil
}

// checkServerCertificate requires a single Ed25519 server-auth leaf issued
// directly by root, currently valid, with DNS names only, whose key matches.
func checkServerCertificate(c tls.Certificate, root *x509.Certificate, now time.Time) (tls.Certificate, error) {
	if len(c.Certificate) != 1 || c.PrivateKey == nil {
		return tls.Certificate{}, errConfig
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil || !bytes.Equal(leaf.Raw, c.Certificate[0]) {
		return tls.Certificate{}, errConfig
	}
	if c.Leaf != nil && !bytes.Equal(c.Leaf.Raw, leaf.Raw) {
		return tls.Certificate{}, errConfig
	}
	if !bytes.Equal(leaf.RawIssuer, root.RawSubject) || leaf.CheckSignatureFrom(root) != nil {
		return tls.Certificate{}, errConfig
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return tls.Certificate{}, errConfig
	}
	if leaf.PublicKeyAlgorithm != x509.Ed25519 || !leaf.BasicConstraintsValid || leaf.IsCA ||
		leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0 ||
		len(leaf.DNSNames) == 0 || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.EmailAddresses) != 0 {
		return tls.Certificate{}, errConfig
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	signer, sok := c.PrivateKey.(ed25519.PrivateKey)
	if !ok || !sok || !pub.Equal(signer.Public()) {
		return tls.Certificate{}, errConfig
	}
	c.Leaf = leaf
	return c, nil
}

// validProcedure accepts "/pkg.Service/Method" in printable ASCII.
func validProcedure(p string) bool {
	if len(p) < 4 || len(p) > maxProcedureBytes || p[0] != '/' || strings.Count(p, "/") != 2 {
		return false
	}
	svc, method, _ := strings.Cut(p[1:], "/")
	if svc == "" || method == "" || !strings.Contains(svc, ".") {
		return false
	}
	for i := range len(p) {
		c := p[i]
		if !(c == '/' || c == '.' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

func validStreamType(t connect.StreamType) bool {
	switch t {
	case connect.StreamTypeUnary, connect.StreamTypeClient, connect.StreamTypeServer, connect.StreamTypeBidi:
		return true
	}
	return false
}
