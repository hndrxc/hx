package domain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

// oracleID recomputes a resource ID independently of NewResourceID using the
// documented framing, so implementation changes cannot mask regressions.
func oracleID(integrationID, scope, kind, nativeKey string) string {
	h := sha256.New()
	io.WriteString(h, resourceIDPrefix)
	var frame [4]byte
	for _, part := range []string{integrationID, scope, kind, nativeKey} {
		binary.BigEndian.PutUint32(frame[:], uint32(len(part)))
		h.Write(frame[:])
		io.WriteString(h, part)
	}
	return resourceIDScheme + hex.EncodeToString(h.Sum(nil))
}

func TestResourceIDDeterministicAndFramingBoundaries(t *testing.T) {
	src := Source{IntegrationID: "acct-01", Scope: "us-east-1"}
	for _, n := range []int{1, 2, 254, 255, 256, 257, 65534, 65535, 65536, 65537, 1 << 20} {
		key := strings.Repeat("k", n)
		first, err := NewResourceID(src, KindService, key)
		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}
		second, err := NewResourceID(src, KindService, key)
		if err != nil {
			t.Fatalf("len %d (repeat): %v", n, err)
		}
		if first != second {
			t.Errorf("len %d: not deterministic: %s vs %s", n, first, second)
		}
		if want := oracleID("acct-01", "us-east-1", "service", key); string(first) != want {
			t.Errorf("len %d: framing mismatch:\n got %s\nwant %s", n, first, want)
		}
	}
}

func TestResourceIDSeparationAndCollisions(t *testing.T) {
	base := Source{IntegrationID: "acct-01", Scope: "us-east-1"}
	baseID, err := NewResourceID(base, KindProject, "proj-9f8e7d6c5b4a3")
	if err != nil {
		t.Fatal(err)
	}

	distinct := []struct {
		name   string
		mutate func() (ResourceID, error)
	}{
		{"integration", func() (ResourceID, error) {
			return NewResourceID(Source{IntegrationID: "acct-02", Scope: "us-east-1"}, KindProject, "proj-9f8e7d6c5b4a3")
		}},
		{"scope", func() (ResourceID, error) {
			return NewResourceID(Source{IntegrationID: "acct-01", Scope: "us-west-2"}, KindProject, "proj-9f8e7d6c5b4a3")
		}},
		{"kind", func() (ResourceID, error) {
			return NewResourceID(base, KindStoragePool, "proj-9f8e7d6c5b4a3")
		}},
		{"native-key", func() (ResourceID, error) {
			return NewResourceID(base, KindProject, "proj-9f8e7d6c5b4a4")
		}},
		{"native-key-case", func() (ResourceID, error) {
			return NewResourceID(base, KindProject, "proj-9F8E7D6C5B4A3")
		}},
		{"native-key-trim", func() (ResourceID, error) {
			return NewResourceID(base, KindProject, " proj-9f8e7d6c5b4a3 ")
		}},
	}
	for _, tc := range distinct {
		if id, err := tc.mutate(); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		} else if id == baseID {
			t.Errorf("%s: got colliding ID %s", tc.name, id)
		}
	}
}

func TestResourceIDValidation(t *testing.T) {
	const key = "proj-x"
	cases := []struct {
		name string
		src  Source
		kind Kind
		key  string
		want error
	}{
		{"empty integration", Source{Scope: "s"}, KindProject, key, ErrEmptyIntegrationID},
		{"empty scope", Source{IntegrationID: "i"}, KindProject, key, ErrEmptyScope},
		{"empty key", Source{IntegrationID: "i", Scope: "s"}, KindProject, "", ErrEmptyNativeKey},
		{"invalid utf-8 integration", Source{IntegrationID: "i\xff", Scope: "s"}, KindProject, key, ErrInvalidUTF8},
		{"invalid utf-8 scope", Source{IntegrationID: "i", Scope: "s\xff"}, KindProject, key, ErrInvalidUTF8},
		{"invalid utf-8 key", Source{IntegrationID: "i", Scope: "s"}, KindProject, "k\xff", ErrInvalidUTF8},
		{"unknown kind", Source{IntegrationID: "i", Scope: "s"}, KindUnknown, key, ErrUnknownKind},
		{"out-of-range kind", Source{IntegrationID: "i", Scope: "s"}, Kind(99), key, ErrUnknownKind},
	}
	for _, tc := range cases {
		if _, err := NewResourceID(tc.src, tc.kind, tc.key); err != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestKindTokens(t *testing.T) {
	if tok, ok := KindProject.Token(); !ok || tok != "project" {
		t.Errorf("KindProject.Token() = %q, %v", tok, ok)
	}
	if tok, ok := KindStoragePool.Token(); !ok || tok != "storage_pool" {
		t.Errorf("KindStoragePool.Token() = %q, %v", tok, ok)
	}
	if tok, ok := KindUnknown.Token(); ok {
		t.Errorf("KindUnknown.Token() = %q, ok; want unusable", tok)
	}
	if k, ok := ParseKind("project"); !ok || k != KindProject {
		t.Errorf("ParseKind(project) = %v, %v", k, ok)
	}
	if k, ok := ParseKind("storage_pool"); !ok || k != KindStoragePool {
		t.Errorf("ParseKind(storage_pool) = %v, %v", k, ok)
	}
	if k, ok := ParseKind("dns_record"); !ok || k != KindDNSRecord {
		t.Errorf("ParseKind(dns_record) = %v, %v", k, ok)
	}
	if k, ok := ParseKind("unknown"); !ok || k != KindUnknown {
		t.Errorf("ParseKind(unknown) = %v, %v", k, ok)
	}
	if _, ok := ParseKind("project "); ok {
		t.Error("ParseKind(project ) accepted untrimmed token")
	}
}
