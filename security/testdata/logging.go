// Fixture for Semgrep rule tests only; never built or executed (testdata is ignored by Go).
package testdata

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
)

type handle struct{}

func (h *handle) Use(ctx context.Context, scope string, fn func(plaintext []byte) error) error {
	return fn(nil)
}

type value struct{}

func (v *value) Use(fn func(plaintext []byte) error) error { return fn(nil) }

func redact(b []byte) string { return "[redacted]" }

func direct(ctx context.Context, h *handle) {
	_ = h.Use(ctx, "token", func(p []byte) error {
		// ruleid: hx-go-secret-use-plaintext-log
		log.Printf("value=%s", p)
		return nil
	})
}

func slogDirect(ctx context.Context, h *handle, l *slog.Logger) {
	_ = h.Use(ctx, "token", func(secretBytes []byte) error {
		// ruleid: hx-go-secret-use-plaintext-log
		l.Info("got", "v", string(secretBytes))
		return nil
	})
}

func alias(ctx context.Context, h *handle) {
	_ = h.Use(ctx, "token", func(p []byte) error {
		s := string(p)
		t := s
		// ruleid: hx-go-secret-use-plaintext-log
		fmt.Println(t)
		return nil
	})
}

func errorSink(ctx context.Context, h *handle) {
	_ = h.Use(ctx, "token", func(p []byte) error {
		// ruleid: hx-go-secret-use-plaintext-log
		return fmt.Errorf("bad value %s", p)
	})
}

func valueUse(v *value) {
	_ = v.Use(func(p []byte) error {
		// ruleid: hx-go-secret-use-plaintext-log
		log.Println(string(p))
		return nil
	})
}

func valueUseError(v *value) {
	_ = v.Use(func(p []byte) error {
		// ruleid: hx-go-secret-use-plaintext-log
		return errors.New(string(p))
	})
}

func localCopies(ctx context.Context, h *handle) {
	_ = h.Use(ctx, "token", func(p []byte) error {
		q := p
		r := q
		s := string(r)
		// ruleid: hx-go-secret-use-plaintext-log
		log.Print(s)
		return nil
	})
}

func errorsNewMetadata(ctx context.Context, h *handle) {
	_ = h.Use(ctx, "token", func(p []byte) error {
		// ok: hx-go-secret-use-plaintext-log
		return errors.New("token rejected")
	})
}

func arbitraryRedactMethod(ctx context.Context, h *handle, x *handle2) {
	_ = h.Use(ctx, "token", func(p []byte) error {
		// ruleid: hx-go-secret-use-plaintext-log
		log.Print(x.Redact(p))
		return nil
	})
}

type handle2 struct{}

func (*handle2) Redact(b []byte) []byte { return b }

func metadataOnly(ctx context.Context, h *handle) {
	_ = h.Use(ctx, "token", func(p []byte) error {
		// ok: hx-go-secret-use-plaintext-log
		log.Printf("len=%d", len(p))
		return nil
	})
}

func redactedWrapper(ctx context.Context, h *handle) {
	_ = h.Use(ctx, "token", func(p []byte) error {
		// ok: hx-go-secret-use-plaintext-log
		log.Printf("value=%s", redact(p))
		return nil
	})
}

func unrelated(ctx context.Context, h *handle) {
	_ = h.Use(ctx, "token", func(p []byte) error {
		return nil
	})
	// ok: hx-go-secret-use-plaintext-log
	log.Printf("scope=%s", "token")
}
