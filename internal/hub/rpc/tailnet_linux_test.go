//go:build linux

package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"

	"github.com/hndrxc/hx/internal/hub/enroll"
)

// listeningTCPInodes returns socket inodes held by this process that are in
// TCP LISTEN state on any host interface.
func listeningTCPInodes(t *testing.T) map[string]bool {
	t.Helper()
	listen := map[string]bool{}
	for _, f := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		fh, err := os.Open(f)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) > 9 && fs[3] == "0A" {
				listen[fs[9]] = true
			}
		}
		fh.Close()
	}
	own := map[string]bool{}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		l, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if err != nil || !strings.HasPrefix(l, "socket:[") {
			continue
		}
		ino := strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")
		if listen[ino] {
			own[ino] = true
		}
	}
	return own
}

func privateStateDir(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(parent, "state")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCheckTailnetEnvRejectsPresenceEvenEmpty(t *testing.T) {
	vars := append([]string{}, prohibitedTailnetEnv...)
	vars = append(vars, "TS_LOG_TARGET", "TS_USE_CONTROL_DIAL_PLAN", "TSNET_FORCE_LOGIN", "TS_NO_LOGS_NO_SUPPORT")
	for _, v := range vars {
		for _, val := range []string{"", "x"} {
			if err := checkTailnetEnv([]string{"HOME=/h", v + "=" + val}); !errors.Is(err, errProhibitedEnv) {
				t.Errorf("%s=%q: err = %v, want prohibited", v, val, err)
			}
		}
	}
	if err := checkTailnetEnv([]string{"HOME=/h", "TS_NO_LOGS_NO_SUPPORT=true", "XTS_AUTHKEY=1"}); err != nil {
		t.Fatalf("benign env rejected: %v", err)
	}
}

func TestServeTailnetProhibitedEnvFailsWithoutListener(t *testing.T) {
	dir := privateStateDir(t)
	before := listeningTCPInodes(t)
	for _, v := range prohibitedTailnetEnv {
		t.Run(v, func(t *testing.T) {
			t.Setenv(v, "")
			called := false
			err := ServeTailnet(context.Background(), dir, Config{}, func(string) { called = true })
			if !errors.Is(err, errProhibitedEnv) {
				t.Fatalf("err = %v, want prohibited env", err)
			}
			if called {
				t.Fatal("login callback invoked")
			}
			if _, err := os.Lstat(filepath.Join(dir, tsnetSubdir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("tsnet state touched before env check")
			}
		})
	}
	if after := listeningTCPInodes(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("host TCP listeners changed: %v -> %v", before, after)
	}
}

func TestServeTailnetUnsafeStateDirFailsWithoutListener(t *testing.T) {
	before := listeningTCPInodes(t)
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(loose, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o750); err != nil {
		t.Fatal(err)
	}
	h := newEndpointHarness(t)
	err := ServeTailnet(context.Background(), loose, h.config(h.methods()), nil)
	if !errors.Is(err, errUnsafeStateDir) {
		t.Fatalf("err = %v, want unsafe state dir", err)
	}
	if after := listeningTCPInodes(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("host TCP listeners changed: %v -> %v", before, after)
	}
}

func TestServeTailnetInvalidConfigTouchesNoState(t *testing.T) {
	dir := privateStateDir(t)
	before := listeningTCPInodes(t)
	if err := ServeTailnet(context.Background(), dir, Config{}, nil); !errors.Is(err, errConfig) {
		t.Fatalf("err = %v, want config error", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, tsnetSubdir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("tsnet state touched before config check")
	}
	if after := listeningTCPInodes(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("host TCP listeners changed: %v -> %v", before, after)
	}
}

// syntheticControlURL is a synthetic, never-contacted non-SaaS control server.
const syntheticControlURL = "https://headscale.example"

func prefsJSON(t *testing.T, controlURL string) []byte {
	t.Helper()
	p := ipn.NewPrefs()
	p.ControlURL = controlURL
	return p.ToBytes()
}

func profilesJSON(t *testing.T, controlURL string) []byte {
	t.Helper()
	b, err := json.Marshal(map[ipn.ProfileID]*ipn.LoginProfile{
		"p1": {ID: "p1", Key: "profile-p1", ControlURL: controlURL},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckTailnetState(t *testing.T) {
	type kv = map[ipn.StateKey][]byte
	cases := []struct {
		name  string
		state kv
		ok    bool
	}{
		{"empty", kv{}, true},
		{"saas default", kv{
			ipn.CurrentProfileStateKey: []byte("profile-p1"),
			ipn.KnownProfilesStateKey:  profilesJSON(t, ""),
			"profile-p1":               prefsJSON(t, ""),
		}, true},
		{"saas explicit", kv{
			ipn.CurrentProfileStateKey: []byte("profile-p1"),
			ipn.KnownProfilesStateKey:  profilesJSON(t, ipn.DefaultControlURL),
			"profile-p1":               prefsJSON(t, ipn.DefaultControlURL),
		}, true},
		{"legacy saas", kv{ipn.LegacyGlobalDaemonStateKey: prefsJSON(t, "")}, true},
		{"profile non-saas", kv{
			ipn.CurrentProfileStateKey: []byte("profile-p1"),
			ipn.KnownProfilesStateKey:  profilesJSON(t, syntheticControlURL),
		}, false},
		{"prefs non-saas", kv{
			ipn.CurrentProfileStateKey: []byte("profile-p1"),
			ipn.KnownProfilesStateKey:  profilesJSON(t, ""),
			"profile-p1":               prefsJSON(t, syntheticControlURL),
		}, false},
		{"synonym not exact", kv{
			ipn.KnownProfilesStateKey: profilesJSON(t, "https://login.tailscale.com"),
		}, false},
		{"legacy non-saas", kv{ipn.LegacyGlobalDaemonStateKey: prefsJSON(t, syntheticControlURL)}, false},
		{"dangling current", kv{ipn.CurrentProfileStateKey: []byte("profile-missing")}, false},
		{"malformed profiles", kv{ipn.KnownProfilesStateKey: []byte("{")}, false},
		{"mismatched profile id", kv{
			ipn.KnownProfilesStateKey: []byte(`{"p1":{"ID":"p2","Key":"profile-p1"}}`),
		}, false},
		{"missing profile key", kv{ipn.KnownProfilesStateKey: []byte(`{"p1":{"ID":"p1"}}`)}, false},
		{"null profile", kv{ipn.KnownProfilesStateKey: []byte(`{"p1":null}`)}, false},
		{"malformed prefs", kv{
			ipn.KnownProfilesStateKey: profilesJSON(t, ""),
			"profile-p1":              []byte("{"),
		}, false},
		{"malformed legacy", kv{ipn.LegacyGlobalDaemonStateKey: []byte("{")}, false},
		{"serve config present", kv{
			ipn.KnownProfilesStateKey: profilesJSON(t, ""),
			ipn.ServeConfigKey("p1"):  []byte(`{"TCP":{"80":{"HTTP":true}}}`),
		}, false},
		{"serve config empty", kv{
			ipn.KnownProfilesStateKey: profilesJSON(t, ""),
			ipn.ServeConfigKey("p1"):  []byte{},
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := new(mem.Store)
			for k, v := range tc.state {
				if err := st.WriteState(k, v); err != nil {
					t.Fatal(err)
				}
			}
			err := checkTailnetState(st)
			if tc.ok != (err == nil) {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err != nil {
				if !errors.Is(err, errUnsafeTailnetState) {
					t.Fatalf("err = %v, want unsafe state", err)
				}
				if strings.Contains(err.Error(), "headscale") || strings.Contains(err.Error(), "profile-") {
					t.Fatalf("error leaks untrusted state: %v", err)
				}
			}
		})
	}
}

func TestServeTailnetNonSaaSStateFailsWithoutListener(t *testing.T) {
	dir := privateStateDir(t)
	_, stateFile, err := prepareTailnetDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := store.NewFileStore(func(string, ...any) {}, stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteState(ipn.LegacyGlobalDaemonStateKey, prefsJSON(t, syntheticControlURL)); err != nil {
		t.Fatal(err)
	}
	before := listeningTCPInodes(t)
	h := newEndpointHarness(t)
	called := false
	err = ServeTailnet(context.Background(), dir, h.config(h.methods()), func(string) { called = true })
	if !errors.Is(err, errUnsafeTailnetState) {
		t.Fatalf("err = %v, want unsafe state", err)
	}
	if called {
		t.Fatal("login callback invoked")
	}
	if after := listeningTCPInodes(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("host TCP listeners changed: %v -> %v", before, after)
	}
}

func TestPrepareTailnetDir(t *testing.T) {
	t.Run("creates private tsnet dir", func(t *testing.T) {
		sd := privateStateDir(t)
		dir, sf, err := prepareTailnetDir(sd)
		if err != nil {
			t.Fatal(err)
		}
		if dir != filepath.Join(sd, "tsnet") || sf != filepath.Join(dir, "tailscaled.state") {
			t.Fatalf("paths %q %q", dir, sf)
		}
		fi, err := os.Lstat(dir)
		if err != nil || fi.Mode().Perm() != 0o700 || !fi.IsDir() {
			t.Fatalf("tsnet dir %v %v", fi, err)
		}
		if _, _, err := prepareTailnetDir(sd); err != nil {
			t.Fatalf("idempotent: %v", err)
		}
	})
	cases := map[string]func(t *testing.T) string{
		"empty":    func(*testing.T) string { return "" },
		"relative": func(*testing.T) string { return "state" },
		"unclean":  func(t *testing.T) string { return privateStateDir(t) + "/" },
		"missing":  func(t *testing.T) string { return filepath.Join(t.TempDir(), "nope") },
		"group readable": func(t *testing.T) string {
			d := privateStateDir(t)
			os.Chmod(d, 0o750)
			return d
		},
		"symlink state dir": func(t *testing.T) string {
			d := privateStateDir(t)
			l := filepath.Join(filepath.Dir(d), "link")
			if err := os.Symlink(d, l); err != nil {
				t.Fatal(err)
			}
			return l
		},
		"symlink ancestor": func(t *testing.T) string {
			d := privateStateDir(t)
			l := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(filepath.Dir(d), l); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(l, "state")
		},
		"writable ancestor": func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "open")
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			os.Chmod(p, 0o777)
			d := filepath.Join(p, "state")
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
			return d
		},
		"loose tsnet dir": func(t *testing.T) string {
			d := privateStateDir(t)
			if err := os.Mkdir(filepath.Join(d, "tsnet"), 0o700); err != nil {
				t.Fatal(err)
			}
			os.Chmod(filepath.Join(d, "tsnet"), 0o755)
			return d
		},
		"symlink tsnet dir": func(t *testing.T) string {
			d := privateStateDir(t)
			other := privateStateDir(t)
			if err := os.Symlink(other, filepath.Join(d, "tsnet")); err != nil {
				t.Fatal(err)
			}
			return d
		},
		"symlink state file": func(t *testing.T) string {
			d := privateStateDir(t)
			ts := filepath.Join(d, "tsnet")
			os.Mkdir(ts, 0o700)
			if err := os.Symlink("/etc/passwd", filepath.Join(ts, "tailscaled.state")); err != nil {
				t.Fatal(err)
			}
			return d
		},
		"loose state file": func(t *testing.T) string {
			d := privateStateDir(t)
			ts := filepath.Join(d, "tsnet")
			os.Mkdir(ts, 0o700)
			f := filepath.Join(ts, "tailscaled.state")
			if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			os.Chmod(f, 0o644)
			return d
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := prepareTailnetDir(mk(t)); !errors.Is(err, errUnsafeStateDir) {
				t.Fatalf("err = %v, want unsafe", err)
			}
		})
	}
}

func TestUserLogfForwardsOnlyVettedLoginURL(t *testing.T) {
	var got []string
	logf := userLogf(func(u string) { got = append(got, u) })
	good := "https://login.tailscale.com/a/abc123"
	logf(authURLFormat, good)
	for _, bad := range []string{
		"http://login.tailscale.com/a/x",
		"https://login.tailscale.com:8443/a/x",
		"https://evil@login.tailscale.com/a/x",
		"https://login.tailscale.com.evil.example/a/x",
		"https://headscale.example/a/x",
		"https://login.tailscale.com/a/x#frag",
		"not a url",
	} {
		logf(authURLFormat, bad)
	}
	logf("some raw tsnet message %s", good)
	logf(authURLFormat, 42)
	if !reflect.DeepEqual(got, []string{good}) {
		t.Fatalf("forwarded %v", got)
	}
	userLogf(nil)(authURLFormat, good) // must not panic
}

func TestMapWhoIs(t *testing.T) {
	ok := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{StableID: "nStable1", User: 12345, Tags: []string{"tag:hx-agent"}},
	}
	p, err := mapWhoIs(ok)
	if err != nil {
		t.Fatal(err)
	}
	want := enroll.TailnetPeer{NodeID: "nStable1", UserID: strconv.Itoa(12345), Tags: []string{"tag:hx-agent"}}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("got %+v want %+v", p, want)
	}
	// Returned tags must not alias the response.
	ok.Node.Tags[0] = "tag:mutated"
	if p.Tags[0] != "tag:hx-agent" {
		t.Fatal("tags alias WhoIs response")
	}
	for name, r := range map[string]*apitype.WhoIsResponse{
		"nil":         nil,
		"no node":     {},
		"no stableid": {Node: &tailcfg.Node{ID: 7, User: 1, Tags: []string{"tag:a"}}},
		"no user":     {Node: &tailcfg.Node{StableID: "n", Tags: []string{"tag:a"}}},
		"no tags":     {Node: &tailcfg.Node{StableID: "n", User: 1}},
		"bad tag":     {Node: &tailcfg.Node{StableID: "n", User: 1, Tags: []string{"hx-agent"}}},
		"empty tag":   {Node: &tailcfg.Node{StableID: "n", User: 1, Tags: []string{"tag:"}}},
	} {
		if _, err := mapWhoIs(r); !errors.Is(err, errWhoIs) {
			t.Errorf("%s: err = %v, want fail closed", name, err)
		}
	}
}

// TestOfflineTailnetListenerExposure starts a real ephemeral tsnet node with no
// credentials inside an isolated (loopback-only) network namespace and proves
// the production listenTailnet path binds only the virtual :443 listener and
// opens no host TCP listener. Run only in the offline Docker scratch runner
// (--network none) with HX_TEST_OFFLINE_TAILNET=1.
func TestOfflineTailnetListenerExposure(t *testing.T) {
	if os.Getenv("HX_TEST_OFFLINE_TAILNET") != "1" {
		t.Skip("set HX_TEST_OFFLINE_TAILNET=1 in an isolated --network none runner")
	}
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback == 0 {
			t.Fatalf("non-loopback interface %q present; refusing to start tsnet outside an isolated network", ifc.Name)
		}
	}
	envknob.SetNoLogsNoSupport()

	discard := func(string, ...any) {}
	ts := &tsnet.Server{
		Dir:           privateStateDir(t),
		Store:         new(mem.Store),
		Hostname:      tailnetHostname,
		ControlURL:    ipn.DefaultControlURL,
		AdvertiseTags: []string{tailnetTag},
		Ephemeral:     true,
		UserLogf:      discard,
		Logf:          discard,
	}
	defer ts.Close()

	before := listeningTCPInodes(t)
	ln, err := listenTailnet(ts)
	if err != nil {
		t.Fatalf("listenTailnet: %v", err)
	}
	defer ln.Close()
	if _, port, err := net.SplitHostPort(ln.Addr().String()); err != nil || port != "443" {
		t.Fatalf("virtual listener addr %q: port %q, err %v; want 443", ln.Addr(), port, err)
	}
	if after := listeningTCPInodes(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("host TCP listeners changed: before %v after %v", before, after)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
