//go:build linux

package rpc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/tsnet"

	"golang.org/x/net/netutil"

	"github.com/hndrxc/hx/internal/hub/enroll"
)

// ADR-0007 fixed tailnet identity of the hub node.
const (
	tailnetHostname = "hx-hub"
	tailnetTag      = "tag:hx-hub"
	tailnetAddr     = ":443"
	tsnetSubdir     = "tsnet"
	stateFileName   = "tailscaled.state"
	shutdownTimeout = 10 * time.Second
	// maxTailnetConns bounds accepted raw tsnet connections (including those
	// stuck in TLS handshake) so they cannot exhaust descriptors/memory.
	maxTailnetConns = 128

	// authURLFormat is the exact format tsnet v1.104.7 uses (tsnet.go
	// printAuthURLLoop) to announce the interactive login URL via UserLogf.
	authURLFormat = "To start this tsnet server, restart with TS_AUTHKEY set, or go to: %s"
	// loginHost is the only accepted interactive login host (Tailscale SaaS).
	loginHost = "login.tailscale.com"
)

// prohibitedTailnetEnv are the ambient credential and control-plane overrides
// tsnet v1.104.7 reads (tsnet.go L769-L812). Presence alone, even empty,
// aborts startup. Any other TS_* / TSNET_* variable is rejected as well since
// it may redirect control, log or DERP upstreams (e.g. TS_LOG_TARGET,
// TS_USE_CONTROL_DIAL_PLAN, TSNET_FORCE_LOGIN).
var prohibitedTailnetEnv = []string{
	"TS_AUTHKEY",
	"TS_AUTH_KEY",
	"TS_CONTROL_URL",
	"TS_CLIENT_SECRET",
	"TS_CLIENT_ID",
	"TS_ID_TOKEN",
	"TS_AUDIENCE",
}

var (
	errProhibitedEnv      = errors.New("rpc: prohibited tailnet environment variable present")
	errUnsafeStateDir     = errors.New("rpc: unsafe tailnet state directory")
	errUnsafeTailnetState = errors.New("rpc: unsafe tailnet saved state")
	errWhoIs              = errors.New("rpc: tailnet identity unavailable")
)

// checkTailnetEnv fails closed if any ADR-0007 prohibited variable or any
// other Tailscale override variable is present in environ. The only accepted
// variable is TS_NO_LOGS_NO_SUPPORT=true, which this package sets itself.
func checkTailnetEnv(environ []string) error {
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		for _, p := range prohibitedTailnetEnv {
			if k == p {
				return fmt.Errorf("%w: %s", errProhibitedEnv, k)
			}
		}
		if k == "TS_NO_LOGS_NO_SUPPORT" && v == "true" {
			continue
		}
		if strings.HasPrefix(k, "TS_") || strings.HasPrefix(k, "TSNET_") {
			return fmt.Errorf("%w: %s", errProhibitedEnv, k)
		}
	}
	return nil
}

// privateDir verifies path is an existing real directory (not a symlink),
// owned by the effective user, with mode exactly 0700.
func privateDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: %v", errUnsafeStateDir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a real directory", errUnsafeStateDir, path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: %s not owned by service user", errUnsafeStateDir, path)
	}
	if fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: %s mode %v, want 0700", errUnsafeStateDir, path, fi.Mode().Perm())
	}
	return nil
}

// prepareTailnetDir validates the hub state dir and returns the private
// "<stateDir>/tsnet" directory and its state file path. Every ancestor must be
// a non-symlink directory owned by root or the service user and not writable
// by group/other, except root-owned sticky directories such as /tmp.
func prepareTailnetDir(stateDir string) (dir, stateFile string, err error) {
	if stateDir == "" || !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return "", "", fmt.Errorf("%w: state dir must be a clean absolute path", errUnsafeStateDir)
	}
	for p := filepath.Dir(stateDir); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return "", "", fmt.Errorf("%w: %v", errUnsafeStateDir, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return "", "", fmt.Errorf("%w: ancestor %s is not a real directory", errUnsafeStateDir, p)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) {
			return "", "", fmt.Errorf("%w: ancestor %s has foreign owner", errUnsafeStateDir, p)
		}
		if fi.Mode().Perm()&0o022 != 0 && (fi.Mode()&os.ModeSticky == 0 || st.Uid != 0) {
			return "", "", fmt.Errorf("%w: ancestor %s is group/other writable", errUnsafeStateDir, p)
		}
		if p == "/" {
			break
		}
	}
	if err := privateDir(stateDir); err != nil {
		return "", "", err
	}
	dir = filepath.Join(stateDir, tsnetSubdir)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", "", fmt.Errorf("%w: %v", errUnsafeStateDir, err)
	}
	if err := privateDir(dir); err != nil {
		return "", "", err
	}
	stateFile = filepath.Join(dir, stateFileName)
	fi, err := os.Lstat(stateFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return "", "", fmt.Errorf("%w: %v", errUnsafeStateDir, err)
	case !fi.Mode().IsRegular():
		return "", "", fmt.Errorf("%w: state file is not a regular file", errUnsafeStateDir)
	case fi.Mode().Perm()&0o077 != 0:
		return "", "", fmt.Errorf("%w: state file mode %v", errUnsafeStateDir, fi.Mode().Perm())
	default:
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
			return "", "", fmt.Errorf("%w: state file not owned by service user", errUnsafeStateDir)
		}
	}
	return dir, stateFile, nil
}

// vetLoginURL accepts only an https://login.tailscale.com URL without
// userinfo, explicit port or fragment.
func vetLoginURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host != loginHost ||
		u.Fragment != "" || u.Opaque != "" {
		return "", false
	}
	return u.String(), true
}

// userLogf receives tsnet user logs; only a vetted login URL is forwarded.
// Raw tsnet messages are never logged.
func userLogf(loginURL func(string)) func(string, ...any) {
	return func(format string, args ...any) {
		if format != authURLFormat || len(args) != 1 || loginURL == nil {
			return
		}
		raw, ok := args[0].(string)
		if !ok {
			return
		}
		if u, ok := vetLoginURL(raw); ok {
			loginURL(u)
		}
	}
}

// mapWhoIs converts a WhoIs response into a TailnetPeer, failing closed on any
// missing node id, user id or tag.
func mapWhoIs(resp *apitype.WhoIsResponse) (enroll.TailnetPeer, error) {
	if resp == nil || resp.Node == nil {
		return enroll.TailnetPeer{}, fmt.Errorf("%w: missing node", errWhoIs)
	}
	n := resp.Node
	if n.StableID.IsZero() {
		return enroll.TailnetPeer{}, fmt.Errorf("%w: missing stable node id", errWhoIs)
	}
	if n.User.IsZero() {
		return enroll.TailnetPeer{}, fmt.Errorf("%w: missing user id", errWhoIs)
	}
	if len(n.Tags) == 0 {
		return enroll.TailnetPeer{}, fmt.Errorf("%w: missing tags", errWhoIs)
	}
	tags := make([]string, 0, len(n.Tags))
	for _, t := range n.Tags {
		if !strings.HasPrefix(t, "tag:") || len(t) == len("tag:") {
			return enroll.TailnetPeer{}, fmt.Errorf("%w: malformed tag", errWhoIs)
		}
		tags = append(tags, t)
	}
	return enroll.TailnetPeer{
		NodeID: string(n.StableID),
		UserID: strconv.FormatInt(int64(n.User), 10),
		Tags:   tags,
	}, nil
}

// allowedControlURL reports whether a saved control URL is Tailscale SaaS:
// unset (upstream default) or exactly ipn.DefaultControlURL.
func allowedControlURL(u string) bool {
	return u == "" || u == ipn.DefaultControlURL
}

// checkSavedPrefs vets the prefs stored under k, mirroring upstream
// profileManager.loadSavedPrefs: missing or empty means defaults.
func checkSavedPrefs(st ipn.StateStore, k ipn.StateKey) error {
	bs, err := st.ReadState(k)
	if errors.Is(err, ipn.ErrStateNotExist) || (err == nil && len(bs) == 0) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: unreadable prefs", errUnsafeTailnetState)
	}
	p := ipn.NewPrefs()
	if err := ipn.PrefsFromBytes(bs, p); err != nil {
		return fmt.Errorf("%w: malformed prefs", errUnsafeTailnetState)
	}
	if !allowedControlURL(p.ControlURL) {
		return fmt.Errorf("%w: prefs use non-SaaS control server", errUnsafeTailnetState)
	}
	return nil
}

// checkTailnetState fails closed unless every saved login profile, the
// startup profile it references, and (absent profiles) the legacy daemon
// prefs that upstream newProfileManagerWithGOOS would load use Tailscale SaaS,
// and no profile has a persisted ServeConfig (ipn.ServeConfigKey). It only
// reads the store. Untrusted state bytes and keys never appear in errors.
//
// Deployment prerequisite (not enforceable here): LocalBackend applies
// syspolicy pkey.ControlURL over prefs (ControlURLOrDefault). In-process
// tsnet on Linux registers no policy store (only cmd/tailscaled loads a JSON
// policy file; the env store is never registered), so any machine policy
// source must be root-managed and is trusted as such.
func checkTailnetState(st ipn.StateStore) error {
	cur, err := st.ReadState(ipn.CurrentProfileStateKey)
	if err != nil && !errors.Is(err, ipn.ErrStateNotExist) {
		return fmt.Errorf("%w: unreadable current profile", errUnsafeTailnetState)
	}
	known := map[ipn.ProfileID]*ipn.LoginProfile{}
	switch b, err := st.ReadState(ipn.KnownProfilesStateKey); {
	case errors.Is(err, ipn.ErrStateNotExist):
	case err != nil:
		return fmt.Errorf("%w: unreadable profiles", errUnsafeTailnetState)
	default:
		if err := json.Unmarshal(b, &known); err != nil {
			return fmt.Errorf("%w: malformed profiles", errUnsafeTailnetState)
		}
	}
	curFound := false
	for id, p := range known {
		if p == nil || id == "" || p.ID != id || p.Key == "" {
			return fmt.Errorf("%w: malformed profile entry", errUnsafeTailnetState)
		}
		if !allowedControlURL(p.ControlURL) {
			return fmt.Errorf("%w: profile uses non-SaaS control server", errUnsafeTailnetState)
		}
		if err := checkSavedPrefs(st, p.Key); err != nil {
			return err
		}
		// hx never writes Serve/Funnel config; any persisted one could
		// expose ports beyond the explicit tsnet.Listen, so reject it.
		switch bs, err := st.ReadState(ipn.ServeConfigKey(id)); {
		case errors.Is(err, ipn.ErrStateNotExist):
		case err != nil:
			return fmt.Errorf("%w: unreadable serve config", errUnsafeTailnetState)
		case len(bs) > 0:
			return fmt.Errorf("%w: persisted serve config present", errUnsafeTailnetState)
		}
		if string(cur) == string(p.Key) {
			curFound = true
		}
	}
	switch {
	case len(cur) > 0 && !curFound:
		return fmt.Errorf("%w: current profile reference invalid", errUnsafeTailnetState)
	case len(cur) == 0 && len(known) == 0:
		return checkSavedPrefs(st, ipn.LegacyGlobalDaemonStateKey)
	}
	return nil
}

// ServeTailnet joins the tailnet as hx-hub (tag:hx-hub) using Tailscale SaaS
// only and serves the RPC handler over TLS on the tsnet-internal :443. It
// opens no host TCP listener. It returns when ctx is done or serving fails.
func ServeTailnet(ctx context.Context, stateDir string, cfg Config, loginURL func(string)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkTailnetEnv(os.Environ()); err != nil {
		return err
	}

	// Build and vet the mTLS server before touching any on-disk state.
	var ts *tsnet.Server
	whoIs := func(ctx context.Context, remoteAddr string) (enroll.TailnetPeer, error) {
		lc, err := ts.LocalClient()
		if err != nil {
			return enroll.TailnetPeer{}, fmt.Errorf("%w: local client", errWhoIs)
		}
		resp, err := lc.WhoIs(ctx, remoteAddr)
		if err != nil {
			return enroll.TailnetPeer{}, fmt.Errorf("%w: lookup failed", errWhoIs)
		}
		return mapWhoIs(resp)
	}
	srv, err := newServer(cfg, whoIs)
	if err != nil {
		return err
	}
	if srv.TLSConfig == nil || srv.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		return errors.New("rpc: tailnet server requires mTLS config")
	}

	dir, stateFile, err := prepareTailnetDir(stateDir)
	if err != nil {
		return err
	}
	envknob.SetNoLogsNoSupport()

	discard := func(string, ...any) {}
	st, err := store.NewFileStore(discard, stateFile)
	if err != nil {
		return fmt.Errorf("rpc: tailnet state store: %w", err)
	}
	// Saved profiles/legacy prefs are vetted before tsnet reads them.
	if err := checkTailnetState(st); err != nil {
		return err
	}
	ts = &tsnet.Server{
		Dir:           dir,
		Store:         st,
		Hostname:      tailnetHostname,
		ControlURL:    ipn.DefaultControlURL,
		AdvertiseTags: []string{tailnetTag},
		UserLogf:      userLogf(loginURL),
		Logf:          discard,
	}
	defer ts.Close()

	ln, err := listenTailnet(ts)
	if err != nil {
		return err
	}
	return serveUntilDone(ctx, srv, ln)
}

// listenTailnet opens the hub's tsnet virtual listener on tailnetAddr, capped
// at maxTailnetConns. LimitListener only wraps the tsnet netstack listener; no
// host socket is opened.
func listenTailnet(ts *tsnet.Server) (net.Listener, error) {
	ln, err := ts.Listen("tcp", tailnetAddr)
	if err != nil {
		return nil, fmt.Errorf("rpc: tsnet listen: %w", err)
	}
	return netutil.LimitListener(ln, maxTailnetConns), nil
}

// serveUntilDone runs srv.ServeTLS on ln and gracefully shuts down on ctx.
func serveUntilDone(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	select {
	case err := <-errc:
		// ServeTLS already returned (and usually closed ln); a close error here is
		// the expected already-closed case and must not mask the serve error.
		_ = ln.Close()
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			// Graceful shutdown timed out; force-close. Its error adds nothing
			// actionable beyond ctx.Err(), which the caller receives below.
			_ = srv.Close()
		}
		<-errc
		return ctx.Err()
	}
}
