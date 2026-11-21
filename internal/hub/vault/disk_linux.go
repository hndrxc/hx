//go:build linux

package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/sys/unix"
)

const (
	vaultFile  = "vault.sealed"
	lockFile   = ".vault.lock"
	tempPrefix = ".vault.sealed.tmp-"
)

// errLocked reports that another process holds the vault lock.
var errLocked = errors.New("vault: locked by another process")

// disk owns a vault directory: an anchored directory fd plus an exclusive
// lock held on a stable sibling lock file for the lifetime of the disk.
// The directory's ancestors are assumed private and trusted.
type disk struct {
	dir   int
	lock  int
	euid  int
	fsync func(fd int) error // private seam for deterministic failure tests
}

// openDisk anchors an existing operator-created directory owned by the
// effective uid with mode 0700 and takes the exclusive writer lock.
func openDisk(dir string) (*disk, error) {
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vault: open dir: %w", err)
	}
	d := &disk{dir: dfd, lock: -1, euid: unix.Geteuid(), fsync: unix.Fsync}
	if err := d.checkDir(); err != nil {
		return nil, errors.Join(err, closeFD(dfd, "dir"))
	}
	lfd, err := d.openLock()
	if err != nil {
		return nil, errors.Join(err, closeFD(dfd, "dir"))
	}
	if err := d.checkFile(lfd, "lock"); err != nil {
		return nil, errors.Join(err, closeFD(lfd, "lock"), closeFD(dfd, "dir"))
	}
	if err := unix.Flock(lfd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		cerr := errors.Join(closeFD(lfd, "lock"), closeFD(dfd, "dir"))
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.Join(errLocked, cerr)
		}
		return nil, errors.Join(fmt.Errorf("vault: lock: %w", err), cerr)
	}
	d.lock = lfd
	return d, nil
}

// closeFD closes fd, wrapping any failure with the descriptor's role.
func closeFD(fd int, what string) error {
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("vault: close %s: %w", what, err)
	}
	return nil
}

// openLock opens the lock file without altering an existing inode; a missing
// lock is created with O_EXCL at 0600. No mode is ever changed: an existing
// lock or one narrowed by an unusual umask fails checkFile closed.
func (d *disk) openLock() (int, error) {
	const flags = unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	for attempt := 0; ; attempt++ {
		fd, err := unix.Openat(d.dir, lockFile, flags, 0)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return -1, fmt.Errorf("vault: open lock: %w", err)
		}
		fd, err = unix.Openat(d.dir, lockFile, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.EEXIST) || attempt > 0 {
			return -1, fmt.Errorf("vault: create lock: %w", err)
		}
	}
}

func (d *disk) checkDir() error {
	var st unix.Stat_t
	if err := unix.Fstat(d.dir, &st); err != nil {
		return fmt.Errorf("vault: stat dir: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("vault: not a directory")
	}
	if int(st.Uid) != d.euid {
		return errors.New("vault: directory not owned by current user")
	}
	if st.Mode&0o7777 != 0o700 {
		return fmt.Errorf("vault: directory mode %#o, want 0700", st.Mode&0o7777)
	}
	return nil
}

// checkFile requires a regular file owned by the effective uid with mode 0600
// and a single link (no hardlink aliasing).
func (d *disk) checkFile(fd int, what string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("vault: stat %s: %w", what, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("vault: %s is not a regular file", what)
	}
	if int(st.Uid) != d.euid {
		return fmt.Errorf("vault: %s not owned by current user", what)
	}
	if st.Mode&0o7777 != 0o600 {
		return fmt.Errorf("vault: %s mode %#o, want 0600", what, st.Mode&0o7777)
	}
	if st.Nlink != 1 {
		return fmt.Errorf("vault: %s has %d links", what, st.Nlink)
	}
	return nil
}

func (d *disk) openTarget() (int, error) {
	fd, err := unix.Openat(d.dir, vaultFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return -1, fs.ErrNotExist
		}
		return -1, fmt.Errorf("vault: open image: %w", err)
	}
	if err := d.checkFile(fd, "image"); err != nil {
		return -1, errors.Join(err, closeFD(fd, "image"))
	}
	return fd, nil
}

// read returns the sealed image, or fs.ErrNotExist when no vault exists.
func (d *disk) read() (_ []byte, err error) {
	fd, err := d.openTarget()
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := closeFD(fd, "image"); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 64<<10)
	for {
		n, err := unix.Read(fd, chunk)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("vault: read image: %w", err)
		}
		if n == 0 {
			return buf, nil
		}
		if len(buf)+n > maxImage {
			return nil, errors.New("vault: image exceeds size limit")
		}
		buf = append(buf, chunk[:n]...)
	}
}

// write atomically replaces the image: temp file in the same directory,
// flush, rename, flush directory. The old image is never truncated. An error
// returned after the rename may mean the new image was committed.
func (d *disk) write(raw []byte) (err error) {
	if len(raw) > maxImage {
		return errors.New("vault: image exceeds size limit")
	}
	if fd, err := d.openTarget(); err == nil {
		// A failed close of the existing image is not ignored: refuse to
		// replace a target whose state we could not cleanly release.
		if cerr := closeFD(fd, "image"); cerr != nil {
			return cerr
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("vault: temp name: %w", err)
	}
	tmp := tempPrefix + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(d.dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("vault: create temp: %w", err)
	}
	renamed := false
	defer func() {
		if fd >= 0 {
			err = errors.Join(err, closeFD(fd, "temp"))
		}
		if !renamed {
			if uerr := unix.Unlinkat(d.dir, tmp, 0); uerr != nil && !errors.Is(uerr, unix.ENOENT) {
				err = errors.Join(err, fmt.Errorf("vault: remove temp: %w", uerr))
			}
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("vault: chmod temp: %w", err)
	}
	if err := d.checkFile(fd, "temp"); err != nil {
		return err
	}
	for p := raw; len(p) > 0; {
		n, err := unix.Write(fd, p)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("vault: write temp: %w", err)
		}
		if n <= 0 {
			return errors.New("vault: write temp: no progress")
		}
		p = p[n:]
	}
	if err := d.fsync(fd); err != nil {
		return fmt.Errorf("vault: sync temp: %w", err)
	}
	cerr := unix.Close(fd)
	fd = -1
	if cerr != nil {
		return fmt.Errorf("vault: close temp: %w", cerr)
	}
	if err := unix.Renameat(d.dir, tmp, d.dir, vaultFile); err != nil {
		return fmt.Errorf("vault: rename: %w", err)
	}
	renamed = true
	if err := d.fsync(d.dir); err != nil {
		return fmt.Errorf("vault: sync dir (image may be committed): %w", err)
	}
	return nil
}

// close releases the lock and directory anchor.
func (d *disk) close() error {
	var err error
	if d.lock >= 0 {
		err = errors.Join(unix.Flock(d.lock, unix.LOCK_UN), unix.Close(d.lock))
		d.lock = -1
	}
	if d.dir >= 0 {
		err = errors.Join(err, unix.Close(d.dir))
		d.dir = -1
	}
	return err
}
