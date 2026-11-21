//go:build linux

package tlstrust

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// dirBackend keeps an exclusively flocked, private directory open for the
// life of the store. All record access goes through the os.Root so names
// cannot escape the directory.
type dirBackend struct {
	root *os.Root
	dir  *os.File
	uid  int
}

func openBackend(dir string) (backend, error) {
	if dir == "" {
		return nil, ErrStore
	}
	uid := os.Geteuid()
	li, err := os.Lstat(dir)
	if err != nil || !li.IsDir() || li.Mode().Perm() != 0o700 || li.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, ErrStore
	}
	if st, ok := li.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid {
		return nil, ErrStore
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, ErrStore
	}
	df, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, ErrStore
	}
	fail := func() (backend, error) {
		_ = df.Close()
		_ = root.Close()
		return nil, ErrStore
	}
	fi, err := df.Stat()
	if err != nil || !os.SameFile(li, fi) {
		return fail()
	}
	sc, err := df.SyscallConn()
	if err != nil {
		return fail()
	}
	var lockErr error
	if err := sc.Control(func(fd uintptr) {
		lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
	}); err != nil || lockErr != nil {
		return fail()
	}
	return &dirBackend{root: root, dir: df, uid: uid}, nil
}

func (b *dirBackend) read(name string) ([]byte, error) {
	// O_NONBLOCK keeps a FIFO from blocking open; O_NOFOLLOW rejects symlinks.
	f, err := b.root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 ||
		fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		int(st.Uid) != b.uid || st.Nlink != 1 || fi.Size() > maxRecordSize {
		return nil, errors.New("tlstrust: unsafe record file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRecordSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRecordSize {
		return nil, errors.New("tlstrust: oversized record")
	}
	return data, nil
}

func (b *dirBackend) write(name string, data []byte) error {
	tmp := name + ".tmp"
	if err := b.root.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := b.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	abort := func(err error) error {
		_ = f.Close()
		_ = b.root.Remove(tmp)
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		return abort(err)
	}
	if _, err := f.Write(data); err != nil {
		return abort(err)
	}
	if err := f.Sync(); err != nil {
		return abort(err)
	}
	if err := f.Close(); err != nil {
		_ = b.root.Remove(tmp)
		return err
	}
	if err := b.root.Rename(tmp, name); err != nil {
		return &commitError{err}
	}
	if err := b.dir.Sync(); err != nil {
		return &commitError{err}
	}
	return nil
}

func (b *dirBackend) close() error {
	derr := b.dir.Close() // releases the flock
	rerr := b.root.Close()
	return errors.Join(derr, rerr)
}
