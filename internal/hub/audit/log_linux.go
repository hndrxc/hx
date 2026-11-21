//go:build linux

package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// OpenOptions controls how an existing log is opened.
type OpenOptions struct {
	// Anchor, when set, must exactly match a checkpoint inside the valid chain.
	Anchor *Checkpoint
	// RecoverTail opts in to truncating a torn (non-LF-terminated) final
	// record. It requires an explicit trusted Anchor (Genesis is allowed).
	RecoverTail bool
}

// ErrLogPoisoned is returned after an ambiguous write or sync failure; the
// persisted state is unknown and the log must be reopened and re-verified.
var ErrLogPoisoned = errors.New("audit: log poisoned by earlier I/O failure")

// ErrLogClosed is returned when using a closed log.
var ErrLogClosed = errors.New("audit: log closed")

// Log is an append-only, durable audit chain writer. The path must be in a
// trusted, private, local directory.
type Log struct {
	mu       sync.Mutex
	f        *os.File
	head     Checkpoint
	poisoned bool
	closed   bool
}

// Open opens the log at path, verifies the whole chain, and takes an
// exclusive non-blocking flock for the lifetime of the Log. A missing file is
// created only for an ordinary unanchored or genesis-anchored open without
// tail recovery; otherwise a missing file is evidence of loss and is refused.
func Open(path string, options OpenOptions) (*Log, error) {
	if options.RecoverTail && options.Anchor == nil {
		return nil, errors.New("audit: tail recovery requires an explicit anchor")
	}
	if options.Anchor != nil && !validAnchor(*options.Anchor) {
		return nil, ErrAnchorInvalid
	}
	flags := unix.O_RDWR | unix.O_APPEND | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	genesisAnchor := options.Anchor == nil || (options.Anchor.Sequence == 0 && options.Anchor.Hash == zeroHash)
	if genesisAnchor && !options.RecoverTail {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Open(path, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open log: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	l, err := initLog(f, path, options)
	if err != nil {
		_ = f.Close() // releases any flock
		return nil, err
	}
	return l, nil
}

func initLog(f *os.File, path string, options OpenOptions) (*Log, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("audit: stat log: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("audit: log is not a regular file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return nil, errors.New("audit: log is not owned by the current user")
	}
	if fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || fi.Mode().Perm() != 0o600 {
		return nil, errors.New("audit: log mode must be 0600")
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("audit: lock log: %w", err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return nil, err
	}

	// Re-stat under the lock so the scanned length is stable.
	if fi, err = f.Stat(); err != nil {
		return nil, fmt.Errorf("audit: stat log: %w", err)
	}
	head, valid, err := scan(io.NewSectionReader(f, 0, fi.Size()), options.Anchor)
	if err != nil {
		if !errors.Is(err, ErrTornTail) || !options.RecoverTail {
			return nil, err
		}
		// ErrTornTail is only returned after the anchor matched.
		if err := f.Truncate(valid); err != nil {
			return nil, fmt.Errorf("audit: truncate torn tail: %w", err)
		}
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("audit: sync log: %w", err)
	}
	return &Log{f: f, head: head}, nil
}

func syncDir(dir string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("audit: open log directory: %w", err)
	}
	d := os.NewFile(uintptr(fd), dir)
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("audit: sync log directory: %w", err)
	}
	return nil
}

// Append durably records event and returns the new head. On success the frame
// has been written and fsynced. Invalid events reserve no sequence. After an
// ambiguous write or sync failure the log is poisoned.
func (l *Log) Append(event Event) (Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return Checkpoint{}, ErrLogClosed
	}
	if l.poisoned {
		return Checkpoint{}, ErrLogPoisoned
	}
	frame, next, err := encode(event, l.head)
	if err != nil {
		return Checkpoint{}, err
	}
	n, err := l.f.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		l.poisoned = true
		return Checkpoint{}, fmt.Errorf("audit: write: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		l.poisoned = true
		return Checkpoint{}, fmt.Errorf("audit: sync: %w", err)
	}
	l.head = next
	return next, nil
}

// Close releases the lock and file. It performs no repair.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrLogClosed
	}
	l.closed = true
	return l.f.Close()
}
