//go:build linux

package secret

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func newBuffer(n int) (*buffer, error) {
	pageSize := os.Getpagesize()
	size := (n + pageSize - 1) &^ (pageSize - 1)
	if size == 0 {
		size = pageSize
	}

	mem, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, fmt.Errorf("secret: allocate protected buffer: %w", err)
	}

	buf := &buffer{
		mem:  mem,
		data: mem[:n],
	}

	if err := unix.Mlock(mem); err != nil {
		buf.locked = false
		buf.lockErr = err
	} else {
		buf.locked = true
	}

	_ = unix.Madvise(mem, unix.MADV_DONTDUMP)

	liveBuffers.Add(1)
	return buf, nil
}

func (b *buffer) release() {
	if b == nil || b.mem == nil {
		return
	}
	if b.locked {
		_ = unix.Munlock(b.mem)
	}
	_ = unix.Munmap(b.mem)
}
