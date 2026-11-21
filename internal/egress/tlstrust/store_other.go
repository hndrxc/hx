//go:build !linux

package tlstrust

import "errors"

var errUnsupported = errors.New("tlstrust: trust store unsupported on this platform")

// openBackend is explicitly unsupported: the store relies on Linux directory
// ownership, mode and flock semantics.
func openBackend(string) (backend, error) {
	return nil, errors.Join(ErrStore, errUnsupported)
}
