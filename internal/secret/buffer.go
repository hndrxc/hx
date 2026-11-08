package secret

import (
	"runtime"
	"sync/atomic"
)

type buffer struct {
	mem     []byte // whole allocation (page-rounded mapping on Linux)
	data    []byte // mem[:n], the plaintext view
	locked  bool
	lockErr error // nil when locked; reason otherwise (never contains plaintext)
}

var liveBuffers atomic.Int64 // incremented in newBuffer, decremented in destroy; tests read it

var wipeObserver func(mem []byte) // nil in production; tests set it to inspect memory after wiping

func (b *buffer) destroy() {
	if b == nil || b.mem == nil {
		return
	}
	clear(b.mem)
	runtime.KeepAlive(b.mem)
	if wipeObserver != nil {
		wipeObserver(b.mem)
	}
	b.release()
	liveBuffers.Add(-1)
	b.mem = nil
	b.data = nil
}
