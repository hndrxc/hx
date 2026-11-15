package secret

import (
	"bytes"
	"runtime"
	"testing"
)

func TestBuffer_LifecycleAndWipe(t *testing.T) {
	baseline := liveBuffers.Load()

	buf, err := newBuffer(64)
	if err != nil {
		t.Fatalf("newBuffer(64) failed: %v", err)
	}

	if got := liveBuffers.Load(); got != baseline+1 {
		t.Fatalf("expected liveBuffers %d, got %d", baseline+1, got)
	}

	for i := range buf.data {
		buf.data[i] = byte(i + 1)
	}

	var observedMem []byte
	wipeObserver = func(mem []byte) {
		observedMem = make([]byte, len(mem))
		copy(observedMem, mem)
	}
	t.Cleanup(func() {
		wipeObserver = nil
	})

	allocLen := len(buf.mem)
	if allocLen < 64 {
		t.Fatalf("expected allocation size >= 64, got %d", allocLen)
	}

	buf.destroy()

	if buf.mem != nil || buf.data != nil {
		t.Fatalf("destroy must set mem and data to nil")
	}

	if got := liveBuffers.Load(); got != baseline {
		t.Fatalf("expected liveBuffers to return to baseline %d, got %d", baseline, got)
	}

	if len(observedMem) != allocLen {
		t.Fatalf("wipeObserver saw length %d, expected %d", len(observedMem), allocLen)
	}

	zeroMem := make([]byte, allocLen)
	if !bytes.Equal(observedMem, zeroMem) {
		t.Fatalf("destroy did not zero full allocation: got %v", observedMem)
	}

	// Repeated destroy on already destroyed buffer must be idempotent and not decrement counter again.
	buf.destroy()
	if got := liveBuffers.Load(); got != baseline {
		t.Fatalf("idempotent destroy changed liveBuffers: expected %d, got %d", baseline, got)
	}
}

func TestBuffer_PlatformLocking(t *testing.T) {
	buf, err := newBuffer(32)
	if err != nil {
		t.Fatalf("newBuffer(32) failed: %v", err)
	}
	defer buf.destroy()

	if runtime.GOOS == "linux" {
		if buf.locked && buf.lockErr != nil {
			t.Fatalf("locked=true but lockErr != nil: %v", buf.lockErr)
		}
		if !buf.locked && buf.lockErr == nil {
			t.Fatalf("locked=false but lockErr == nil")
		}
		// Usable allocation even if mlock failed degraded
		if len(buf.data) != 32 {
			t.Fatalf("expected buf.data length 32, got %d", len(buf.data))
		}
	} else {
		if buf.locked {
			t.Fatalf("expected locked=false on !linux, got true")
		}
		if buf.lockErr == nil {
			t.Fatalf("expected lockErr != nil on !linux")
		}
	}
}
