//go:build linux

package ipc

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/hndrxc/hx/internal/hub/audit"
)

// Errors reported by the Linux Unix-socket transport.
var (
	ErrUnixPeerDenied   = errors.New("ipc: unix peer credentials not authorized")
	ErrUnixUnsafePath   = errors.New("ipc: unsafe unix socket path")
	ErrUnixSocketExists = errors.New("ipc: unix socket path already exists")
)

const (
	maxSymlinkHops = 40
	// sun_path is 108 bytes including the terminating NUL.
	maxSunPath = 107
	socketMode = 0o660
)

// ListenUnix binds an AF_UNIX stream socket at path and returns a Listener
// that authorizes each accepted connection from kernel SO_PEERCRED data.
//
// Peers are admitted when their UID equals the service's effective UID, or
// when their effective (primary) GID equals adminGID. Supplementary groups are
// deliberately NOT consulted: SO_PEERCRED only reports the effective GID, and
// reading supplementary groups from /proc is racy against PID reuse. Admins
// must therefore run the client with adminGID as their effective group (for
// example via `sg`/newgrp or a setgid client binary).
//
// The parent directory of path must be owned by the service UID, must not be
// writable by group or other, and must be traversable by adminGID (group
// execute with matching group) or by other. Every ancestor must be owned by
// root or the service UID and not group/other writable unless it is a
// root-owned sticky directory (e.g. /tmp). Symlinks are only followed when
// owned by root inside an already-verified directory (e.g. /var/run -> /run).
//
// An existing entry at path is never unlinked; ListenUnix fails instead. The
// socket is created inside a private 0700 temporary directory, given the
// service owner, adminGID group and mode 0660, and only then hard-linked into
// place, so it is never reachable with umask-derived permissions. Close only
// unlinks path if it still refers to the inode this listener created.
func ListenUnix(path string, adminGID uint32, hooks audit.Hooks) (*Listener, error) {
	uid, err := currentUID()
	if err != nil {
		return nil, err
	}
	raw, err := bindUnix(path, adminGID)
	if err != nil {
		return nil, err
	}
	return newListener(raw, unixAuthorizer(uid, adminGID), hooks), nil
}

// currentUID returns the effective UID after checking it fits a kernel uid_t.
func currentUID() (uint32, error) {
	euid := os.Geteuid()
	if euid < 0 || uint64(euid) > math.MaxUint32 {
		return 0, fmt.Errorf("ipc: effective uid %d out of range", euid)
	}
	return uint32(euid), nil
}

// unixAuthorizer returns the per-connection authorizer for accepted sockets.
// The actor ID is returned even on denial so the attempt can be attributed.
func unixAuthorizer(serviceUID, adminGID uint32) func(net.Conn) (audit.ID, error) {
	return func(c net.Conn) (audit.ID, error) {
		cred, err := peerCred(c)
		if err != nil {
			return audit.ID{}, err
		}
		id := unixActorID(cred.Uid)
		if !authorizePeer(cred.Uid, cred.Gid, serviceUID, adminGID) {
			return id, fmt.Errorf("%w: uid=%d gid=%d", ErrUnixPeerDenied, cred.Uid, cred.Gid)
		}
		return id, nil
	}
}

// authorizePeer is the pure admission policy over kernel-reported credentials.
func authorizePeer(peerUID, peerGID, serviceUID, adminGID uint32) bool {
	return peerUID == serviceUID || peerGID == adminGID
}

// unixActorID is a stable opaque, domain-separated hash of the peer UID.
func unixActorID(uid uint32) audit.ID {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uid)
	h := sha256.New()
	h.Write([]byte("hx/ipc/unix-peer-uid/v1\x00"))
	h.Write(b[:])
	var id audit.ID
	copy(id[:], h.Sum(nil))
	return id
}

func peerCred(c net.Conn) (*unix.Ucred, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("%w: connection is not a unix socket", ErrUnixPeerDenied)
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var serr error
	if err := rc.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, fmt.Errorf("ipc: SO_PEERCRED: %w", serr)
	}
	return cred, nil
}

// unixRaw is the bound socket; Close unlinks only the inode it created.
type unixRaw struct {
	*net.UnixListener
	addr  *net.UnixAddr
	dirfd int
	name  string
	dev   uint64
	ino   uint64
	once  sync.Once
	err   error
}

func (l *unixRaw) Addr() net.Addr { return l.addr }

func (l *unixRaw) Close() error {
	l.once.Do(func() {
		l.err = l.UnixListener.Close()
		var st unix.Stat_t
		if unix.Fstatat(l.dirfd, l.name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil &&
			st.Dev == l.dev && st.Ino == l.ino {
			// The parent is service-owned and not writable by others, so
			// only this service could swap the entry between check and unlink.
			_ = unix.Unlinkat(l.dirfd, l.name, 0)
		}
		_ = unix.Close(l.dirfd)
	})
	return l.err
}

func bindUnix(path string, adminGID uint32) (_ *unixRaw, err error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: %q is not absolute", ErrUnixUnsafePath, path)
	}
	path = filepath.Clean(path)
	name := filepath.Base(path)
	if name == "/" || name == "." || name == ".." || strings.HasPrefix(name, ".hx-ipc-") {
		return nil, fmt.Errorf("%w: invalid socket name %q", ErrUnixUnsafePath, name)
	}
	uid, err := currentUID()
	if err != nil {
		return nil, err
	}
	dir, err := resolveTrustedDir(filepath.Dir(path), uid, adminGID)
	if err != nil {
		return nil, err
	}
	final := filepath.Join(dir, name)
	if len(final) > maxSunPath {
		return nil, fmt.Errorf("%w: path too long for sun_path", ErrUnixUnsafePath)
	}

	dirfd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("ipc: open socket dir: %w", err)
	}
	defer func() {
		if err != nil {
			_ = unix.Close(dirfd)
		}
	}()
	var dst unix.Stat_t
	if err := unix.Fstat(dirfd, &dst); err != nil {
		return nil, err
	}
	if err := checkDir(&dst, uid, adminGID, true); err != nil {
		return nil, err
	}
	var st unix.Stat_t
	switch err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case err == nil:
		return nil, fmt.Errorf("%w: %s", ErrUnixSocketExists, final)
	case !errors.Is(err, unix.ENOENT):
		return nil, err
	}

	tmp, err := os.MkdirTemp(dir, ".hx-ipc-")
	if err != nil {
		return nil, fmt.Errorf("ipc: private socket dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	// MkdirTemp creates the directory with mode 0700 (narrowed further by
	// umask); verify instead of chmodding so the mode can never be widened.
	tmpfd, err := unix.Open(tmp, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("ipc: open private socket dir: %w", err)
	}
	defer unix.Close(tmpfd)
	var tst unix.Stat_t
	if err := unix.Fstat(tmpfd, &tst); err != nil {
		return nil, err
	}
	if tst.Uid != uid || tst.Mode&0o077 != 0 {
		return nil, fmt.Errorf("%w: private socket dir is not private", ErrUnixUnsafePath)
	}
	tmpSock := filepath.Join(tmp, "s")
	if len(tmpSock) > maxSunPath {
		return nil, fmt.Errorf("%w: path too long for sun_path", ErrUnixUnsafePath)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmpSock, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("ipc: bind: %w", err)
	}
	ln.SetUnlinkOnClose(false)
	defer func() {
		if err != nil {
			_ = ln.Close()
		}
	}()
	// Inside the private 0700 directory nobody else can reach or swap tmpSock.
	if err := unix.Fchownat(tmpfd, "s", int(uid), int(adminGID), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, fmt.Errorf("ipc: chown socket to admin gid %d: %w", adminGID, err)
	}
	// Linux fchmodat has no NOFOLLOW; the entry is anchored to the private
	// directory fd and only this process can create or swap entries there.
	if err := unix.Fchmodat(tmpfd, "s", socketMode, 0); err != nil {
		return nil, err
	}
	// linkat refuses an existing target, so a concurrently created entry is
	// never replaced.
	if err := unix.Linkat(unix.AT_FDCWD, tmpSock, dirfd, name, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("%w: %s", ErrUnixSocketExists, final)
		}
		return nil, fmt.Errorf("ipc: publish socket: %w", err)
	}
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uid || st.Gid != adminGID ||
		st.Mode&0o7777 != socketMode {
		_ = unix.Unlinkat(dirfd, name, 0)
		return nil, fmt.Errorf("%w: published socket has unexpected metadata", ErrUnixUnsafePath)
	}
	return &unixRaw{
		UnixListener: ln,
		addr:         &net.UnixAddr{Name: final, Net: "unix"},
		dirfd:        dirfd,
		name:         name,
		dev:          st.Dev,
		ino:          st.Ino,
	}, nil
}

// resolveTrustedDir walks p from the root, verifying each component and
// following only root-owned symlinks, and returns the physical directory.
func resolveTrustedDir(p string, uid, adminGID uint32) (string, error) {
	var st unix.Stat_t
	if err := unix.Lstat("/", &st); err != nil {
		return "", err
	}
	if err := checkDir(&st, uid, adminGID, p == "/"); err != nil {
		return "", fmt.Errorf("%s: %w", "/", err)
	}
	cur := "/"
	rest := strings.Split(strings.TrimPrefix(filepath.Clean(p), "/"), "/")
	hops := 0
	for len(rest) > 0 {
		comp := rest[0]
		rest = rest[1:]
		if comp == "" || comp == "." {
			continue
		}
		if comp == ".." {
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, comp)
		if err := unix.Lstat(next, &st); err != nil {
			return "", fmt.Errorf("ipc: socket dir %s: %w", next, err)
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			if st.Uid != 0 {
				return "", fmt.Errorf("%w: %s is a non-root symlink", ErrUnixUnsafePath, next)
			}
			if hops++; hops > maxSymlinkHops {
				return "", fmt.Errorf("%w: too many symlinks", ErrUnixUnsafePath)
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(target) {
				cur = "/"
			}
			rest = append(strings.Split(filepath.Clean(target), "/"), rest...)
			continue
		}
		if err := checkDir(&st, uid, adminGID, len(rest) == 0); err != nil {
			return "", fmt.Errorf("%s: %w", next, err)
		}
		cur = next
	}
	if cur != filepath.Clean(p) {
		// Re-check the final physical directory under the strict rule when
		// the path ended in a symlink or "..".
		if err := unix.Lstat(cur, &st); err != nil {
			return "", err
		}
		if err := checkDir(&st, uid, adminGID, true); err != nil {
			return "", fmt.Errorf("%s: %w", cur, err)
		}
	}
	return cur, nil
}

// checkDir validates one directory. Ancestors must be owned by root or the
// service and not writable by others unless root-owned and sticky. The socket
// parent must be service-owned, not group/other writable, and traversable by
// the admin group.
func checkDir(st *unix.Stat_t, uid, adminGID uint32, parent bool) error {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: not a directory", ErrUnixUnsafePath)
	}
	mode := st.Mode & 0o7777
	if !parent {
		if st.Uid != 0 && st.Uid != uid {
			return fmt.Errorf("%w: ancestor owned by untrusted uid %d", ErrUnixUnsafePath, st.Uid)
		}
		if mode&0o022 != 0 && (st.Uid != 0 || mode&unix.S_ISVTX == 0) {
			return fmt.Errorf("%w: ancestor writable by untrusted users", ErrUnixUnsafePath)
		}
		return nil
	}
	if st.Uid != uid {
		return fmt.Errorf("%w: socket dir owned by uid %d, want %d", ErrUnixUnsafePath, st.Uid, uid)
	}
	if mode&0o022 != 0 {
		return fmt.Errorf("%w: socket dir writable by group or other", ErrUnixUnsafePath)
	}
	if mode&0o001 == 0 && (st.Gid != adminGID || mode&0o010 == 0) {
		return fmt.Errorf("%w: socket dir not traversable by admin gid %d", ErrUnixUnsafePath, adminGID)
	}
	return nil
}
