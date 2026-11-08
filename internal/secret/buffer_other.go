//go:build !linux

package secret

import "errors"

var errLockUnsupported = errors.New("memory locking unsupported on this platform")

func newBuffer(n int) (*buffer, error) {
	mem := make([]byte, n)
	buf := &buffer{
		mem:     mem,
		data:    mem[:n],
		locked:  false,
		lockErr: errLockUnsupported,
	}
	liveBuffers.Add(1)
	return buf, nil
}

func (b *buffer) release() {
	// Heap allocation on !linux targets is released via GC after clearing.
}
