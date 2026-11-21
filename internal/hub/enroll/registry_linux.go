//go:build linux

package enroll

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"

	"golang.org/x/sys/unix"
)

// The registry stores only public authorization facts: enrolled IDs, roles,
// bindings and certificate fingerprints. It never holds key material.
const (
	registryFile       = "registry.json"
	registryLockFile   = ".registry.lock"
	registryTempPrefix = ".registry.json.tmp-"
	registryVersion    = 1
	maxRegistryEntries = 4096
	maxRegistryImage   = 8 << 20
)

var (
	// errRegistryLocked reports that another process holds the writer lock.
	errRegistryLocked = errors.New("enroll: registry locked by another process")
	// errRegistryCorrupt reports a present but non-canonical or invalid image.
	errRegistryCorrupt = errors.New("enroll: registry image corrupt")
	// errRegistryInvalid reports a refused save of an invalid record set.
	errRegistryInvalid = errors.New("enroll: registry records invalid")
	// errRegistryUnsafe reports an unsafe directory or file on disk.
	errRegistryUnsafe = errors.New("enroll: registry storage unsafe")
)

type registryImage struct {
	Version int             `json:"version"`
	Entries []registryEntry `json:"entries"`
}

type registryEntry struct {
	ID          string `json:"id"`
	Role        uint8  `json:"role"`
	NodeID      string `json:"node_id"`
	UserID      string `json:"user_id"`
	Tag         string `json:"tag"`
	Fingerprint string `json:"fingerprint"`
}

// registryDisk owns a registry directory: an anchored directory fd plus an
// exclusive flock on a stable sibling lock file for its lifetime. The
// directory's ancestors are assumed private and trusted.
type registryDisk struct {
	dir   int
	lock  int
	euid  int
	fsync func(fd int) error // private seam for deterministic failure tests
}

// openRegistry anchors an existing operator-created 0700 directory owned by
// the effective uid, takes the writer lock and loads the records. A missing
// state file yields an empty map; a present but invalid one fails closed.
func openRegistry(dir string) (*registryDisk, map[ID]record, error) {
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: open registry dir: %w", err)
	}
	d := &registryDisk{dir: dfd, lock: -1, euid: unix.Geteuid(), fsync: unix.Fsync}
	if err := d.checkDir(); err != nil {
		return nil, nil, errors.Join(err, registryCloseFD(dfd, "dir"))
	}
	lfd, err := d.openLock()
	if err != nil {
		return nil, nil, errors.Join(err, registryCloseFD(dfd, "dir"))
	}
	if err := d.checkFile(lfd, "lock"); err != nil {
		return nil, nil, errors.Join(err, registryCloseFD(lfd, "lock"), registryCloseFD(dfd, "dir"))
	}
	if err := unix.Flock(lfd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		cerr := errors.Join(registryCloseFD(lfd, "lock"), registryCloseFD(dfd, "dir"))
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, nil, errors.Join(errRegistryLocked, cerr)
		}
		return nil, nil, errors.Join(fmt.Errorf("enroll: registry lock: %w", err), cerr)
	}
	d.lock = lfd
	raw, err := d.read()
	if errors.Is(err, fs.ErrNotExist) {
		return d, map[ID]record{}, nil
	}
	if err != nil {
		return nil, nil, errors.Join(err, d.close())
	}
	recs, err := decodeRegistry(raw)
	if err != nil {
		return nil, nil, errors.Join(err, d.close())
	}
	return d, recs, nil
}

// save atomically replaces the image with recs. An error returned after the
// rename may mean the new image was committed.
func (d *registryDisk) save(recs map[ID]record) error {
	raw, err := encodeRegistry(recs)
	if err != nil {
		return err
	}
	return d.write(raw)
}

// close releases the lock and directory anchor.
func (d *registryDisk) close() error {
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

// encodeRegistry produces the canonical image: entries sorted by ID, fixed
// field order, lowercase hex, no trailing newline.
func encodeRegistry(recs map[ID]record) ([]byte, error) {
	if len(recs) > maxRegistryEntries {
		return nil, errRegistryInvalid
	}
	img := registryImage{Version: registryVersion, Entries: make([]registryEntry, 0, len(recs))}
	for id, r := range recs {
		if id != r.ID || id.IsZero() || !validRecord(r) {
			return nil, errRegistryInvalid
		}
		img.Entries = append(img.Entries, registryEntry{
			ID:          hex.EncodeToString(r.ID[:]),
			Role:        uint8(r.Role),
			NodeID:      r.Binding.NodeID,
			UserID:      r.Binding.UserID,
			Tag:         r.Binding.Tag,
			Fingerprint: hex.EncodeToString(r.Fingerprint[:]),
		})
	}
	slices.SortFunc(img.Entries, func(a, b registryEntry) int {
		return bytes.Compare([]byte(a.ID), []byte(b.ID))
	})
	raw, err := json.Marshal(img)
	if err != nil {
		return nil, errRegistryInvalid
	}
	if len(raw) > maxRegistryImage {
		return nil, errRegistryInvalid
	}
	return raw, nil
}

// decodeRegistry accepts only the exact canonical encoding: it decodes
// strictly, validates every record and requires re-encoding to reproduce the
// input byte for byte, which rejects duplicate keys, reordering, whitespace,
// alternate escapes and trailing material.
func decodeRegistry(raw []byte) (map[ID]record, error) {
	if len(raw) == 0 || len(raw) > maxRegistryImage {
		return nil, errRegistryCorrupt
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var img registryImage
	if err := dec.Decode(&img); err != nil {
		return nil, errRegistryCorrupt
	}
	if img.Version != registryVersion || img.Entries == nil || len(img.Entries) > maxRegistryEntries {
		return nil, errRegistryCorrupt
	}
	recs := make(map[ID]record, len(img.Entries))
	for _, e := range img.Entries {
		var r record
		if !decodeHexExact(r.ID[:], e.ID) || !decodeHexExact(r.Fingerprint[:], e.Fingerprint) {
			return nil, errRegistryCorrupt
		}
		r.Role = Role(e.Role)
		r.Binding = Binding{NodeID: e.NodeID, UserID: e.UserID, Tag: e.Tag}
		if r.ID.IsZero() || !validRecord(r) {
			return nil, errRegistryCorrupt
		}
		if _, dup := recs[r.ID]; dup {
			return nil, errRegistryCorrupt
		}
		recs[r.ID] = r
	}
	again, err := encodeRegistry(recs)
	if err != nil || !bytes.Equal(again, raw) {
		return nil, errRegistryCorrupt
	}
	return recs, nil
}

func decodeHexExact(dst []byte, s string) bool {
	if len(s) != 2*len(dst) {
		return false
	}
	n, err := hex.Decode(dst, []byte(s))
	return err == nil && n == len(dst)
}

// registryCloseFD closes fd, wrapping any failure with the descriptor's role.
func registryCloseFD(fd int, what string) error {
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("enroll: close registry %s: %w", what, err)
	}
	return nil
}

// openLock opens the lock file without altering an existing inode; a missing
// lock is created with O_EXCL at 0600 and then checked, never chmodded.
func (d *registryDisk) openLock() (int, error) {
	const flags = unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	for attempt := 0; ; attempt++ {
		fd, err := unix.Openat(d.dir, registryLockFile, flags, 0)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return -1, fmt.Errorf("enroll: open registry lock: %w", err)
		}
		fd, err = unix.Openat(d.dir, registryLockFile, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.EEXIST) || attempt > 0 {
			return -1, fmt.Errorf("enroll: create registry lock: %w", err)
		}
	}
}

func (d *registryDisk) checkDir() error {
	var st unix.Stat_t
	if err := unix.Fstat(d.dir, &st); err != nil {
		return fmt.Errorf("enroll: stat registry dir: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != d.euid || st.Mode&0o7777 != 0o700 {
		return fmt.Errorf("%w: directory", errRegistryUnsafe)
	}
	return nil
}

// checkFile requires a regular file owned by the effective uid with mode 0600
// and a single link (no hardlink aliasing).
func (d *registryDisk) checkFile(fd int, what string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("enroll: stat registry %s: %w", what, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != d.euid || st.Mode&0o7777 != 0o600 || st.Nlink != 1 {
		return fmt.Errorf("%w: %s", errRegistryUnsafe, what)
	}
	return nil
}

func (d *registryDisk) openTarget() (int, error) {
	fd, err := unix.Openat(d.dir, registryFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return -1, fs.ErrNotExist
		}
		if errors.Is(err, unix.ELOOP) {
			return -1, fmt.Errorf("%w: state", errRegistryUnsafe)
		}
		return -1, fmt.Errorf("enroll: open registry state: %w", err)
	}
	if err := d.checkFile(fd, "state"); err != nil {
		return -1, errors.Join(err, registryCloseFD(fd, "state"))
	}
	return fd, nil
}

// read returns the bounded image, or fs.ErrNotExist when no state exists.
func (d *registryDisk) read() (_ []byte, err error) {
	fd, err := d.openTarget()
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := registryCloseFD(fd, "state"); cerr != nil {
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
			return nil, fmt.Errorf("enroll: read registry state: %w", err)
		}
		if n == 0 {
			return buf, nil
		}
		if len(buf)+n > maxRegistryImage {
			return nil, errRegistryCorrupt
		}
		buf = append(buf, chunk[:n]...)
	}
}

// write atomically replaces the image: fresh temp file in the same directory,
// fsync, rename, fsync directory. The old image is never truncated.
func (d *registryDisk) write(raw []byte) (err error) {
	if d.dir < 0 || d.lock < 0 {
		return errRegistryUnsafe
	}
	if fd, err := d.openTarget(); err == nil {
		if cerr := registryCloseFD(fd, "state"); cerr != nil {
			return cerr
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("enroll: registry temp name: %w", err)
	}
	tmp := registryTempPrefix + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(d.dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("enroll: create registry temp: %w", err)
	}
	renamed := false
	defer func() {
		if fd >= 0 {
			err = errors.Join(err, registryCloseFD(fd, "temp"))
		}
		if !renamed {
			if uerr := unix.Unlinkat(d.dir, tmp, 0); uerr != nil && !errors.Is(uerr, unix.ENOENT) {
				err = errors.Join(err, fmt.Errorf("enroll: remove registry temp: %w", uerr))
			}
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("enroll: chmod registry temp: %w", err)
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
			return fmt.Errorf("enroll: write registry temp: %w", err)
		}
		if n <= 0 {
			return errors.New("enroll: write registry temp: no progress")
		}
		p = p[n:]
	}
	if err := d.fsync(fd); err != nil {
		return fmt.Errorf("enroll: sync registry temp: %w", err)
	}
	cerr := unix.Close(fd)
	fd = -1
	if cerr != nil {
		return fmt.Errorf("enroll: close registry temp: %w", cerr)
	}
	if err := unix.Renameat(d.dir, tmp, d.dir, registryFile); err != nil {
		return fmt.Errorf("enroll: registry rename: %w", err)
	}
	renamed = true
	if err := d.fsync(d.dir); err != nil {
		return fmt.Errorf("enroll: sync registry dir (state may be committed): %w", err)
	}
	return nil
}
