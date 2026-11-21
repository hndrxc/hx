//go:build linux

package ipc

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const helperDialEnv = "HX_IPC_TEST_DIAL"

// socketDir returns a service-owned, admin-traversable directory.
func socketDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAuthorizePeerPolicy(t *testing.T) {
	const svc, admin = 1000, 2000
	cases := []struct {
		name     string
		uid, gid uint32
		want     bool
	}{
		{"same uid", svc, 5, true},
		{"admin effective gid", 4242, admin, true},
		{"other uid and gid", 4242, 4243, false},
		{"root not special", 0, 0, false},
		{"service gid alone", 4242, svc, false},
	}
	for _, c := range cases {
		if got := authorizePeer(c.uid, c.gid, svc, admin); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	a1, a1again := unixActorID(1), unixActorID(1)
	if a1 == unixActorID(2) || a1 != a1again || unixActorID(0).IsZero() {
		t.Fatal("actor IDs must be stable, distinct and non-zero")
	}
}

func TestBindUnixPermissionsAndSameUIDPeer(t *testing.T) {
	path := filepath.Join(socketDir(t), "hub.sock")
	gid := uint32(os.Getegid())
	l, err := bindUnix(path, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 ||
		st.Uid != uint32(os.Geteuid()) || st.Gid != gid {
		t.Fatalf("socket metadata: mode=%v uid=%d gid=%d", fi.Mode(), st.Uid, st.Gid)
	}
	if l.Addr().String() != path {
		t.Fatalf("addr %q", l.Addr())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary entries left behind: %v", entries)
	}

	// A unix connect completes against the backlog, so dial synchronously
	// and accept under a deadline.
	peer, err := net.DialTimeout("unix", path, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := l.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id, err := unixAuthorizer(uint32(os.Geteuid()), gid)(c)
	if err != nil || id != unixActorID(uint32(os.Geteuid())) {
		t.Fatalf("same-uid peer: id=%v err=%v", id, err)
	}
	// Different service UID and admin GID: kernel creds must be denied.
	if _, err := unixAuthorizer(uint32(os.Geteuid())+1, gid+1)(c); !errors.Is(err, ErrUnixPeerDenied) {
		t.Fatalf("want denial, got %v", err)
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket not removed on close: %v", err)
	}
}

func TestAuthorizerRejectsNonUnixConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := unixAuthorizer(0, 0)(a); !errors.Is(err, ErrUnixPeerDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestBindUnixRefusesExistingPath(t *testing.T) {
	gid := uint32(os.Getegid())
	dir := socketDir(t)
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bindUnix(file, gid); !errors.Is(err, ErrUnixSocketExists) {
		t.Fatalf("regular file: %v", err)
	}
	if b, _ := os.ReadFile(file); string(b) != "keep" {
		t.Fatal("existing file modified")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := bindUnix(link, gid); !errors.Is(err, ErrUnixSocketExists) {
		t.Fatalf("symlink: %v", err)
	}
	sock := filepath.Join(dir, "s.sock")
	l, err := bindUnix(sock, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := bindUnix(sock, gid); !errors.Is(err, ErrUnixSocketExists) {
		t.Fatalf("live socket: %v", err)
	}
}

func TestBindUnixRejectsUnsafePaths(t *testing.T) {
	gid := uint32(os.Getegid())
	base := socketDir(t)

	writable := filepath.Join(base, "gw")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o770); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(base, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(real, 0o750); err != nil {
		t.Fatal(err)
	}
	viaLink := filepath.Join(base, "via")
	if err := os.Symlink(real, viaLink); err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(base, "f")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for name, p := range map[string]string{
		"relative":            "hub.sock",
		"group writable dir":  filepath.Join(writable, "hub.sock"),
		"untraversable dir":   filepath.Join(private, "hub.sock"),
		"user symlink parent": filepath.Join(viaLink, "hub.sock"),
		"missing parent":      filepath.Join(base, "missing", "hub.sock"),
		"file parent":         filepath.Join(notDir, "hub.sock"),
		"reserved name":       filepath.Join(real, ".hx-ipc-x"),
		"too long":            filepath.Join(real, string(make([]byte, 120))),
	} {
		if l, err := bindUnix(p, gid); err == nil {
			l.Close()
			t.Errorf("%s: bind succeeded", name)
		}
	}
	if l, err := bindUnix(filepath.Join(real, "ok.sock"), gid); err != nil {
		t.Fatalf("control: %v", err)
	} else {
		l.Close()
	}
}

func TestCloseDoesNotUnlinkReplacement(t *testing.T) {
	path := filepath.Join(socketDir(t), "hub.sock")
	l, err := bindUnix(path, uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if b, err := os.ReadFile(path); err != nil || string(b) != "replacement" {
		t.Fatalf("replacement removed: %v", err)
	}
}

// TestHelperDial is the child half of TestCrossUIDPeer.
func TestHelperDial(t *testing.T) {
	path := os.Getenv(helperDialEnv)
	if path == "" {
		t.Skip("helper process only")
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		os.Exit(3)
	}
	var b [1]byte
	_, _ = c.Read(b[:])
	os.Exit(0)
}

// TestCrossUIDPeer dials from a genuinely distinct UID. Unprivileged user
// namespaces cannot help: SO_PEERCRED translates back to the caller's real
// UID, so this needs root to drop a child to another credential.
func TestCrossUIDPeer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("cross-UID peer test requires root to spawn a child with a distinct UID")
	}
	const childUID, childGID = 65534, 65534
	dir := socketDir(t)
	for d := dir; d != "/" && d != filepath.Clean(os.TempDir()); d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o751); err != nil {
			t.Fatal(err)
		}
	}
	bin := copyTestBinary(t, filepath.Join(dir, "ipc.test"))
	rootGID := uint32(os.Getegid())

	// startChild runs TestHelperDial as childUID/childGID, bounded by ctx.
	startChild := func(t *testing.T, path string) *exec.Cmd {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, bin, "-test.run=^TestHelperDial$")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), helperDialEnv+"="+path)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: childUID, Gid: childGID}}
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cancel()
			_ = cmd.Wait()
		})
		return cmd
	}
	accept := func(t *testing.T, l *unixRaw) net.Conn {
		t.Helper()
		if err := l.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		c, err := l.Accept()
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		return c
	}

	t.Run("kernel denies foreign uid on 0660", func(t *testing.T) {
		path := filepath.Join(dir, "kernel.sock")
		l, err := bindUnix(path, rootGID)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		cmd := startChild(t, path)
		var ee *exec.ExitError
		if err := cmd.Wait(); !errors.As(err, &ee) || ee.ExitCode() != 3 {
			t.Fatalf("child must fail to connect (exit 3), got %v", err)
		}
		// Nothing may be queued: an immediate deadline must time out.
		if err := l.SetDeadline(time.Now()); err != nil {
			t.Fatal(err)
		}
		if c, err := l.Accept(); err == nil {
			c.Close()
			t.Fatal("kernel admitted a foreign peer")
		}
	})

	t.Run("peercred denies foreign uid on widened fixture", func(t *testing.T) {
		path := filepath.Join(dir, "widened.sock")
		l, err := bindUnix(path, rootGID)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		// Deliberately widen only this disposable fixture socket so the
		// SO_PEERCRED check is exercised as defense in depth.
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		startChild(t, path)
		c := accept(t, l)
		defer c.Close()
		id, err := unixAuthorizer(uint32(os.Geteuid()), rootGID)(c)
		if !errors.Is(err, ErrUnixPeerDenied) {
			t.Fatalf("want peer denial, got %v", err)
		}
		if id != unixActorID(childUID) {
			t.Fatal("actor id must reflect the kernel peer UID")
		}
	})

	t.Run("admin effective gid allowed on 0660", func(t *testing.T) {
		path := filepath.Join(dir, "admin.sock")
		l, err := bindUnix(path, childGID)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if fi, err := os.Lstat(path); err != nil || fi.Mode().Perm() != 0o660 {
			t.Fatalf("socket mode: %v %v", fi, err)
		}
		startChild(t, path)
		c := accept(t, l)
		defer c.Close()
		id, err := unixAuthorizer(uint32(os.Geteuid()), childGID)(c)
		if err != nil || id != unixActorID(childUID) {
			t.Fatalf("admin peer: id=%v err=%v", id, err)
		}
	})
}

// copyTestBinary copies the running test binary to dst with mode 0755 so a
// dropped-privilege child can execute it from a traversable directory.
func copyTestBinary(t *testing.T, dst string) string {
	t.Helper()
	src, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}
