package secret

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// Redacted is the sentinel replacement string emitted by all Value formatting
// and serialization routines.
const Redacted = "[REDACTED]"

// MaxSize is the upper limit in bytes for a secret value.
const MaxSize = 64 << 10

// Value represents a secret whose plaintext is stored in protected memory and
// wiped on destruction. All formatting and encoding methods redact the value.
// Shallow copies of Value share the underlying protected state.
type Value struct {
	s *state
}

type state struct {
	mu  sync.RWMutex
	buf *buffer
}

// FromBytes allocates protected memory, copies b into it, and returns a new Value.
//
// FromBytes always zeroes b before returning, including on every error.
// It returns ErrEmpty if b is empty, ErrTooLarge if len(b) > MaxSize, or a wrapped
// allocation error if protected memory could not be allocated.
// The caller owns the returned Value and must call Destroy, normally via defer.
func FromBytes(b []byte) (*Value, error) {
	defer clear(b)
	if len(b) == 0 {
		return nil, ErrEmpty
	}
	if len(b) > MaxSize {
		return nil, ErrTooLarge
	}
	buf, err := newBuffer(len(b))
	if err != nil {
		return nil, err
	}
	copy(buf.data, b)
	return &Value{
		s: &state{
			buf: buf,
		},
	}, nil
}

// Use invokes fn with a direct view of the secret's plaintext.
// The plaintext slice is only valid for the duration of fn.
//
// A nil receiver, an uninitialized Value, or a destroyed Value returns ErrDestroyed.
// fn must not retain or modify the slice. Furthermore, fn must not call Destroy,
// Use, or Locked on the same Value (or any shared copy), because doing so may
// deadlock if a Destroy call is pending.
func (v *Value) Use(fn func(plaintext []byte) error) error {
	if v == nil || v.s == nil {
		return ErrDestroyed
	}
	v.s.mu.RLock()
	defer v.s.mu.RUnlock()
	if v.s.buf == nil {
		return ErrDestroyed
	}
	return fn(v.s.buf.data)
}

// Destroy zeroes and releases the underlying secret buffer.
// It is idempotent and nil-safe. Destroy waits for in-flight Use calls to complete.
func (v *Value) Destroy() {
	if v == nil || v.s == nil {
		return
	}
	v.s.mu.Lock()
	defer v.s.mu.Unlock()
	if v.s.buf == nil {
		return
	}
	v.s.buf.destroy()
	v.s.buf = nil
}

// Locked reports whether the underlying buffer memory is locked in RAM.
// It returns false if the receiver is nil, uninitialized, or destroyed.
func (v *Value) Locked() bool {
	if v == nil || v.s == nil {
		return false
	}
	v.s.mu.RLock()
	defer v.s.mu.RUnlock()
	return v.s.buf != nil && v.s.buf.locked
}

// String returns Redacted for all secret values.
func (v Value) String() string {
	return Redacted
}

// GoString returns Redacted for all secret values.
func (v Value) GoString() string {
	return Redacted
}

// Format writes Redacted for every formatting verb, ensuring no plaintext leaks.
func (v Value) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, Redacted)
}

// MarshalJSON returns the JSON-encoded redacted representation.
func (v Value) MarshalJSON() ([]byte, error) {
	return []byte("\"" + Redacted + "\""), nil
}

// MarshalText returns the textual redacted representation.
func (v Value) MarshalText() ([]byte, error) {
	return []byte(Redacted), nil
}

// LogValue returns a redacted slog attribute value.
func (v Value) LogValue() slog.Value {
	return slog.StringValue(Redacted)
}

// UnmarshalJSON refuses to decode secrets from JSON.
func (v *Value) UnmarshalJSON([]byte) error {
	return ErrIngestionForbidden
}

// UnmarshalText refuses to decode secrets from text, configuration or flags.
func (v *Value) UnmarshalText([]byte) error {
	return ErrIngestionForbidden
}
