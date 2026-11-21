// Package probe is an inert scanner fixture. It is never executed; it exists
// so staticcheck and gosec have known findings to detect.
package probe

import (
	"crypto/md5"
	"encoding/hex"
	"regexp"
)

// WeakDigest illustrates a weak hash (gosec G401/G501).
func WeakDigest(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// InvalidPattern is scanned, never called (staticcheck SA1000).
func InvalidPattern() *regexp.Regexp { return regexp.MustCompile("[") }
