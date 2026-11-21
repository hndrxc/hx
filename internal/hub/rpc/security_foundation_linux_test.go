//go:build linux && securityfoundation

package rpc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/hndrxc/hx/internal/client"
	"github.com/hndrxc/hx/internal/hub/audit"
	"github.com/hndrxc/hx/internal/hub/enroll"
)

// Fixture-only values. The credential is a per-run synthetic marker generated
// from crypto/rand, never a real provider token; the WhoIs identity is fixed
// and never comes from tailnet.
var sfFixtureCredential = "hx-s09-synthetic-fixture-" + rand.Text()

const (
	sfProcedure   = "/hx.test.securityfoundation.v1.SecurityFoundationService/Read"
	sfSourceID    = "security.foundation.fixture"
	sfNodeID      = "node-s09-fixture"
	sfUserID      = "user-s09-fixture"
	sfClientTag   = "tag:hx-client"
	sfTestTimeout = 20 * time.Second
	sfServerName  = "hx-hub.s09.fixture.invalid"
)

var sfReadSpec = connect.Spec{StreamType: connect.StreamTypeUnary, Procedure: sfProcedure}

// sfAuditRecorder wraps the real append-only log, keeping the head checkpoint
// and the action/outcome sequence (never payloads) for later verification.
type sfAuditRecorder struct {
	log    *audit.Log
	mu     sync.Mutex
	head   audit.Checkpoint
	events []audit.Event
}

func (r *sfAuditRecorder) Append(ev audit.Event) (audit.Checkpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp, err := r.log.Append(ev)
	if err != nil {
		return cp, err
	}
	r.head = cp
	r.events = append(r.events, ev)
	return cp, nil
}

func (r *sfAuditRecorder) snapshot() (audit.Checkpoint, []audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.head, append([]audit.Event(nil), r.events...)
}

func sfPrivateDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal("security foundation: private dir create failed")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal("security foundation: private dir chmod failed")
	}
	return dir
}

// sfEphemeralCA builds a fresh Ed25519 enrollment CA and its authority; the
// same root issues the hub server certificate.
func sfEphemeralCA(t *testing.T) (*enroll.Authority, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("security foundation: CA key generation failed")
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hx s09 fixture enrollment CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal("security foundation: CA certificate creation failed")
	}
	a, err := enroll.NewAuthority(der, func(_ context.Context, use func(crypto.Signer) error) error {
		return use(key)
	})
	if err != nil {
		t.Fatal("security foundation: authority construction failed")
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("security foundation: CA certificate parse failed")
	}
	return a, root, key
}

// sfServerCertificate issues an ephemeral DNS-named hub TLS identity from
// the fixture root.
func sfServerCertificate(t *testing.T, root *x509.Certificate, rootKey ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("security foundation: server key generation failed")
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: sfServerName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{sfServerName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, pub, rootKey)
	if err != nil {
		t.Fatal("security foundation: server certificate creation failed")
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// sfFixtureWhoIs is the fixture-only verified identity source: a loopback
// remote resolves to the single fixed tailnet peer; anything else fails
// closed. It never contacts a tailnet.
func sfFixtureWhoIs(_ context.Context, remoteAddr string) (enroll.TailnetPeer, error) {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil || !ap.Addr().Unmap().IsLoopback() {
		return enroll.TailnetPeer{}, errWhoIs
	}
	return enroll.TailnetPeer{NodeID: sfNodeID, UserID: sfUserID, Tags: []string{sfClientTag}}, nil
}

// sfDialStats counts client TLS connections and any that failed to
// negotiate HTTP/2.
type sfDialStats struct {
	dials atomic.Int64
	nonH2 atomic.Int64
}

func sfNewHTTPClient(t *testing.T, roots *x509.CertPool, cert tls.Certificate, stats *sfDialStats) *http.Client {
	t.Helper()
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		ServerName:   sfServerName,
	}
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   cfg,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &tls.Dialer{Config: cfg.Clone()}
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			stats.dials.Add(1)
			if c.(*tls.Conn).ConnectionState().NegotiatedProtocol != "h2" {
				stats.nonH2.Add(1)
			}
			return c, nil
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: sfTestTimeout}
}

func sfRead(ctx context.Context, hc *http.Client, baseURL string) (string, error) {
	c := connect.NewClient(connecthttp.NewTransport(hc, baseURL))
	res := &wrapperspb.StringValue{}
	if err := c.CallUnary(ctx, sfReadSpec, &emptypb.Empty{}, res); err != nil {
		return "", err
	}
	return res.GetValue(), nil
}

var errSFProvider = errors.New("security foundation: provider fixture failed")

// sfReadHandler is the test-only read method. The provider fetch runs only
// inside the vault credential callback, and only production-sanitized text
// leaves it.
func sfReadHandler(
	withCredential func(context.Context, func([]byte) error) error,
	fetch func(context.Context, []byte) (string, error),
	calls *atomic.Int64,
	callers chan<- enroll.ID,
) connect.ServerFunc {
	return func(ctx context.Context, _ connect.Spec, stream connect.ServerStream) error {
		calls.Add(1)
		if err := stream.Receive(&emptypb.Empty{}); err != nil {
			return connect.NewError(connect.CodeInvalidArgument, "invalid request")
		}
		id, ok := Caller(ctx)
		if !ok || id.IsZero() {
			return connect.NewError(connect.CodePermissionDenied, "permission denied")
		}
		select {
		case callers <- id:
		default:
		}
		var display string
		err := withCredential(ctx, func(cred []byte) error {
			raw, err := fetch(ctx, cred)
			if err != nil {
				return errSFProvider
			}
			view, err := client.NewTextView(sfSourceID, "provider fixture", raw)
			if err != nil {
				return errSFProvider
			}
			display = view.Body().String()
			return nil
		})
		if err != nil {
			return connect.NewError(connect.CodeUnavailable, "provider fixture unavailable")
		}
		return stream.Send(wrapperspb.String(display))
	}
}

// sfCheckDisplay compares the client-received payload without dumping it.
func sfCheckDisplay(t *testing.T, got string) {
	t.Helper()
	if got != securityProviderDisplay {
		t.Fatalf("security foundation: sanitized payload mismatch (len got %d, want %d)", len(got), len(securityProviderDisplay))
	}
	if strings.Contains(got, sfFixtureCredential) {
		t.Fatal("security foundation: credential marker reached client")
	}
	if strings.ContainsAny(got, "\x1b\x9b\x9d\x07") {
		t.Fatal("security foundation: terminal control reached client")
	}
}

func sfCheckNoLeak(t *testing.T, what string, b []byte) {
	t.Helper()
	if bytes.Contains(b, []byte(sfFixtureCredential)) {
		t.Fatalf("security foundation: credential marker present in %s", what)
	}
	if bytes.Contains(b, []byte(securityProviderText)) {
		t.Fatalf("security foundation: raw provider text present in %s", what)
	}
	if bytes.ContainsAny(b, "\x1b\x9b\x9d") {
		t.Fatalf("security foundation: terminal control present in %s", what)
	}
}

func sfCodeDenied(err error) bool {
	if err == nil {
		return false
	}
	c := connect.CodeOf(err)
	return c == connect.CodePermissionDenied || c == connect.CodeUnauthenticated
}

type sfStep struct {
	action  audit.Action
	outcome audit.Outcome
}

// sfMatchSteps finds want as an ordered subsequence of events and returns the
// matched indices, or nil. Counts are deliberately not asserted.
func sfMatchSteps(events []audit.Event, want []sfStep) []int {
	idx := make([]int, 0, len(want))
	for i, ev := range events {
		if len(idx) == len(want) {
			break
		}
		w := want[len(idx)]
		if ev.Action == w.action && ev.Outcome == w.outcome {
			idx = append(idx, i)
		}
	}
	if len(idx) != len(want) {
		return nil
	}
	return idx
}

func TestSecurityFoundation(t *testing.T) {
	if securityProviderText == securityProviderDisplay {
		t.Fatal("security foundation: provider fixture must require sanitization")
	}
	ctx, cancel := context.WithTimeout(context.Background(), sfTestTimeout)
	defer cancel()

	auditPath := filepath.Join(sfPrivateDir(t, "audit"), "audit.log")
	auditLog, err := audit.Open(auditPath, audit.OpenOptions{})
	if err != nil {
		t.Fatal("security foundation: audit log open failed")
	}
	t.Cleanup(func() { _ = auditLog.Close() })
	rec := &sfAuditRecorder{log: auditLog}
	hooks := audit.NewHooks(rec)

	authority, caCert, caKey := sfEphemeralCA(t)
	svc, err := enroll.Open(sfPrivateDir(t, "registry"), authority, hooks)
	if err != nil {
		t.Fatal("security foundation: enrollment service open failed")
	}
	t.Cleanup(func() { _ = svc.Close() })

	withCredential := newSecurityVault(t, hooks, sfFixtureCredential)
	fetch := newSecurityProvider(t, hooks, sfFixtureCredential)

	// Enroll a read-role client through the real approve/enroll flow.
	signer, csr, err := client.NewEnrollmentKey()
	if err != nil {
		t.Fatal("security foundation: client key generation failed")
	}
	operator := enroll.LocalPeer{ID: audit.ID{0x5a, 0x09, 0x01}, Operator: true}
	binding := enroll.Binding{NodeID: sfNodeID, UserID: sfUserID, Tag: sfClientTag}
	tok, err := svc.Approve(ctx, operator, binding, enroll.RoleRead, csr)
	if err != nil {
		t.Fatal("security foundation: approval failed")
	}
	peer, err := sfFixtureWhoIs(ctx, "127.0.0.1:1")
	if err != nil {
		t.Fatal("security foundation: fixture identity failed")
	}
	cred, err := svc.Enroll(ctx, peer, tok, csr)
	if err != nil {
		t.Fatal("security foundation: enrollment failed")
	}
	if err := client.VerifyIssuedLeaf(signer, cred.CertificateDER, cred.RootDER); err != nil {
		t.Fatal("security foundation: issued leaf rejected by client")
	}

	// Hub: production server seam over loopback with real TLS and HTTP/2.
	var calls atomic.Int64
	callers := make(chan enroll.ID, 4)
	serverCert := sfServerCertificate(t, caCert, caKey)
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(caCert)
	srv, err := newServer(Config{
		TLSCertificate: serverCert,
		RootDER:        cred.RootDER,
		Enrollment:     svc,
		Audit:          hooks,
		Methods: []Method{{
			Action: enroll.ActionRead,
			Method: connect.Method{Spec: sfReadSpec, Handler: sfReadHandler(withCredential, fetch, &calls, callers)},
		}},
	}, sfFixtureWhoIs)
	if err != nil {
		t.Fatal("security foundation: server construction failed")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("security foundation: loopback listen failed")
	}
	baseURL := "https://" + ln.Addr().String()
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.ServeTLS(ln, "", "") }()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer scancel()
			if err := srv.Shutdown(sctx); err != nil {
				_ = srv.Close()
				t.Error("security foundation: graceful shutdown failed")
			}
			select {
			case err := <-serveDone:
				if !errors.Is(err, http.ErrServerClosed) {
					t.Error("security foundation: serve ended unexpectedly")
				}
			case <-time.After(5 * time.Second):
				t.Error("security foundation: serve did not return")
			}
		})
	}
	t.Cleanup(stop)

	clientCert := tls.Certificate{Certificate: [][]byte{cred.CertificateDER}, PrivateKey: signer}

	// Authorized read over a single HTTP/2 connection.
	stats := &sfDialStats{}
	hc := sfNewHTTPClient(t, serverRoots, clientCert, stats)
	got, err := sfRead(ctx, hc, baseURL)
	if err != nil {
		t.Fatalf("security foundation: authorized read failed (code %v)", connect.CodeOf(err))
	}
	sfCheckDisplay(t, got)
	select {
	case id := <-callers:
		if id != cred.ID {
			t.Fatal("security foundation: caller identity mismatch")
		}
	default:
		t.Fatal("security foundation: caller identity not observed")
	}
	callsBefore := calls.Load()

	// Revoke, then the same connection and a fresh one must both be denied.
	if err := svc.Revoke(ctx, operator, cred.ID); err != nil {
		t.Fatal("security foundation: revoke failed")
	}
	if got, err := sfRead(ctx, hc, baseURL); !sfCodeDenied(err) || got != "" {
		t.Fatalf("security foundation: revoked client read on same connection not denied (code %v)", connect.CodeOf(err))
	}
	if n := stats.dials.Load(); n != 1 {
		t.Fatalf("security foundation: expected one reused connection, got %d", n)
	}
	freshStats := &sfDialStats{}
	fresh := sfNewHTTPClient(t, serverRoots, clientCert, freshStats)
	if got, err := sfRead(ctx, fresh, baseURL); !sfCodeDenied(err) || got != "" {
		t.Fatalf("security foundation: revoked client read on fresh connection not denied (code %v)", connect.CodeOf(err))
	}
	if freshStats.dials.Load() == 0 {
		t.Fatal("security foundation: fresh connection not dialed")
	}
	if stats.nonH2.Load() != 0 || freshStats.nonH2.Load() != 0 {
		t.Fatal("security foundation: connection did not negotiate HTTP/2")
	}
	if calls.Load() != callsBefore {
		t.Fatal("security foundation: handler ran for revoked client")
	}
	hc.CloseIdleConnections()
	fresh.CloseIdleConnections()
	stop()

	// Audit: verify the real on-disk chain against the recorded checkpoint.
	head, events := rec.snapshot()
	if head.Sequence == 0 {
		t.Fatal("security foundation: no audit checkpoint recorded")
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal("security foundation: audit log read failed")
	}
	verified, err := audit.Verify(bytes.NewReader(raw), &head)
	if err != nil || verified != head {
		t.Fatal("security foundation: audit chain verification failed")
	}
	idx := sfMatchSteps(events, []sfStep{
		{audit.ActionClientEnrollment, audit.OutcomeAllowed}, // approve
		{audit.ActionClientEnrollment, audit.OutcomeAllowed}, // enroll
		{audit.ActionAPIAuth, audit.OutcomeAllowed},          // authorized read
		{audit.ActionSecretAccess, audit.OutcomeAllowed},     // vault credential use
		{audit.ActionClientEnrollment, audit.OutcomeAllowed}, // revoke
		{audit.ActionAPIAuth, audit.OutcomeDenied},           // revoked read
	})
	if idx == nil {
		t.Fatal("security foundation: required audit action/outcome order missing")
	}
	if ev := events[idx[2]]; ev.ActorKind != audit.ActorClient || ev.ActorID != cred.ID {
		t.Fatal("security foundation: authorized read audited for wrong actor")
	}
	if ev := events[idx[4]]; ev.ActorKind != audit.ActorOperator || ev.ActorID != operator.ID {
		t.Fatal("security foundation: revoke audited for wrong actor")
	}
	for _, ev := range events[idx[4]+1:] {
		if ev.Outcome == audit.OutcomeAllowed && (ev.Action == audit.ActionAPIAuth || ev.Action == audit.ActionSecretAccess) {
			t.Fatal("security foundation: access allowed after revoke")
		}
	}
	sfCheckNoLeak(t, "audit log", raw)

	t.Log("S09 evidence: read-role client enrolled via real CA and registry, read sanitized provider text over loopback TLS 1.3 HTTP/2 Connect")
	t.Log("S09 evidence: revoked client denied on the same connection and on a fresh connection; handler not reached")
	t.Log("S09 evidence: anchored audit chain verified with approve, enroll, api_auth, secret_access, revoke, denied order")
	t.Log("S09 evidence: no credential marker, raw provider text or terminal control in response or audit log")

	t.Run("audit corruption fails closed", func(t *testing.T) {
		lines := bytes.SplitAfter(raw, []byte("\n"))
		if len(lines) < 2 || len(lines[0]) < 4 {
			t.Fatal("security foundation: audit log too short to tamper")
		}
		flipped := bytes.Clone(raw)
		flipped[len(lines[0])/2] ^= 0x01
		truncated := bytes.Clone(raw[:len(raw)-len(lines[len(lines)-1])])
		if len(lines[len(lines)-1]) == 0 { // trailing empty split element
			truncated = bytes.Clone(raw[:len(raw)-len(lines[len(lines)-2])])
		}
		cases := []struct {
			name string
			b    []byte
		}{
			{"flipped byte", flipped},
			{"dropped tail record", truncated},
			{"torn tail", raw[:len(raw)-1]},
		}
		for _, tc := range cases {
			cp, err := audit.Verify(bytes.NewReader(tc.b), &head)
			if err == nil || cp != (audit.Checkpoint{}) {
				t.Fatalf("security foundation: tampered audit log (%s) accepted", tc.name)
			}
			if !errors.Is(err, audit.ErrCorrupt) && !errors.Is(err, audit.ErrTornTail) &&
				!errors.Is(err, audit.ErrAnchorMissing) && !errors.Is(err, audit.ErrAnchorMismatch) {
				t.Fatalf("security foundation: tampered audit log (%s) wrong error category", tc.name)
			}
		}
		t.Log("S09 evidence: flipped, truncated and torn audit logs fail anchored verification")
	})
}
