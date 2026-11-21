// Fixture for Semgrep rule tests only; never built or executed (testdata is ignored by Go).
package testdata

import "crypto/tls"

func configs(c *tls.Config) {
	// ruleid: hx-go-insecure-skip-verify
	_ = &tls.Config{InsecureSkipVerify: true}

	// ruleid: hx-go-insecure-skip-verify
	_ = &tls.Config{InsecureSkipVerify: false}

	// ruleid: hx-go-insecure-skip-verify
	c.InsecureSkipVerify = false

	// ok: hx-go-insecure-skip-verify
	if c.InsecureSkipVerify {
		return
	}

	// ruleid: hx-go-insecure-skip-verify
	_ = tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	// ruleid: hx-go-insecure-skip-verify
	c.InsecureSkipVerify = true

	// ok: hx-go-insecure-skip-verify
	_ = &tls.Config{MinVersion: tls.VersionTLS13}

	// ok: hx-go-insecure-skip-verify
	_ = c.MinVersion
}
