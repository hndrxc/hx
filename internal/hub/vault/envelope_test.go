package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/hndrxc/hx/internal/secret"
)

func envelopeValue(t *testing.T, s string) *secret.Value {
	t.Helper()
	v, err := secret.FromBytes([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Destroy)
	return v
}

func plain(t *testing.T, v *secret.Value) string {
	t.Helper()
	var s string
	if err := v.Use(func(b []byte) error { s = string(b); return nil }); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDeriveKEKKnownAnswer(t *testing.T) {
	salt := make([]byte, saltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	got := deriveKEK([]byte("correct horse battery staple"), salt)
	const want = "853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e"
	if hex.EncodeToString(got) != want {
		t.Fatalf("KEK = %x, want %s", got, want)
	}
}

func envelopeFixture(t *testing.T) (*envelope, *secret.Value, []byte) {
	t.Helper()
	e, dek, err := newEnvelope(envelopeValue(t, "pass"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dek.Destroy)
	for _, kv := range []struct{ i, s, v string }{{"github", "token", "gh"}, {"cloudflare", "api", "cf"}, {"github", "app", "ga"}} {
		if err := e.put(dek, key{secret.IntegrationID(kv.i), secret.Scope(kv.s)}, envelopeValue(t, kv.v)); err != nil {
			t.Fatal(err)
		}
	}
	img, err := e.encode(dek)
	if err != nil {
		t.Fatal(err)
	}
	return e, dek, img
}

func TestRoundTrip(t *testing.T) {
	_, _, img := envelopeFixture(t)
	d, err := decodeEnvelope(img)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.unlock(envelopeValue(t, "wrong")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong pass: %v", err)
	}
	dek, err := d.unlock(envelopeValue(t, "pass"))
	if err != nil {
		t.Fatal(err)
	}
	defer dek.Destroy()
	v, err := d.open(dek, key{"github", "token"})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Destroy()
	if plain(t, v) != "gh" {
		t.Fatal("wrong plaintext")
	}
	if _, err := d.open(dek, key{"github", "nope"}); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := d.remove(key{"github", "nope"}); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("remove missing: %v", err)
	}
	again, err := d.encode(dek)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(again, img) {
		t.Fatal("re-encode reused image nonce")
	}
}

func TestRewrapAndFreshNonces(t *testing.T) {
	e, dek, img := envelopeFixture(t)
	if err := e.rewrap(dek, envelopeValue(t, "new")); err != nil {
		t.Fatal(err)
	}
	img2, err := e.encode(dek)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(img[:headerSize], img2[:headerSize]) {
		t.Fatal("rewrap reused salt/nonce")
	}
	d, err := decodeEnvelope(img2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.unlock(envelopeValue(t, "pass")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("old pass: %v", err)
	}
	k, err := d.unlock(envelopeValue(t, "new"))
	if err != nil {
		t.Fatal(err)
	}
	k.Destroy()

	k1 := key{"github", "token"}
	r1 := e.records[k1]
	if err := e.put(dek, k1, envelopeValue(t, "gh")); err != nil {
		t.Fatal(err)
	}
	if e.records[k1].nonce == r1.nonce || bytes.Equal(e.records[k1].ct, r1.ct) {
		t.Fatal("put reused nonce")
	}
}

func TestPlaintextAbsent(t *testing.T) {
	e, dek, err := newEnvelope(envelopeValue(t, "pass"))
	if err != nil {
		t.Fatal(err)
	}
	defer dek.Destroy()
	const s = "super-secret-plaintext-marker"
	if err := e.put(dek, key{"github", "token"}, envelopeValue(t, s)); err != nil {
		t.Fatal(err)
	}
	img, err := e.encode(dek)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(img, []byte(s)) {
		t.Fatal("plaintext in image")
	}
}

func TestEveryByteAuthenticated(t *testing.T) {
	_, dek, img := envelopeFixture(t)
	for i := range img {
		m := bytes.Clone(img)
		m[i] ^= 0x01
		d, err := decodeEnvelope(m)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("byte %d: %v", i, err)
			}
			continue
		}
		if err := d.verify(dek); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("byte %d: tamper accepted: %v", i, err)
		}
	}
	// End-to-end: a tampered record ciphertext fails unlock.
	m := bytes.Clone(img)
	m[len(m)-trailerSize-1] ^= 0x80
	d, err := decodeEnvelope(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.unlock(envelopeValue(t, "pass")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("unlock tampered: %v", err)
	}
}

func TestTruncationAndExtension(t *testing.T) {
	_, _, img := envelopeFixture(t)
	for n := range len(img) {
		if _, err := decodeEnvelope(img[:n]); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("prefix %d: %v", n, err)
		}
	}
	if _, err := decodeEnvelope(append(bytes.Clone(img), 0)); !errors.Is(err, ErrCorrupt) {
		t.Fatal("trailing byte accepted")
	}
	if _, err := decodeEnvelope(make([]byte, maxImage+1)); !errors.Is(err, ErrCorrupt) {
		t.Fatal("oversize accepted")
	}
}

func TestParamsRejectedBeforeKDF(t *testing.T) {
	_, _, img := envelopeFixture(t)
	for _, off := range []int{8, 10, 11, 15, 19} { // version, kdf, mem, passes, lanes
		m := bytes.Clone(img)
		m[off] ^= 0x01
		if _, err := decodeEnvelope(m); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("param offset %d accepted: %v", off, err)
		}
	}
}

func TestRecordBinding(t *testing.T) {
	e, dek, _ := envelopeFixture(t)
	a, b := key{"github", "token"}, key{"github", "app"}
	e.records[a] = e.records[b]
	if _, err := e.open(dek, a); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("swapped record opened: %v", err)
	}
}

func TestDecodeRejectsNonCanonical(t *testing.T) {
	e, dek, _ := envelopeFixture(t)
	// Duplicate/unsorted records: build body with records out of order by hand.
	img, err := e.encode(dek)
	if err != nil {
		t.Fatal(err)
	}
	keys := e.sortedKeys()
	off := headerSize + wrappedSize + 4
	r0 := recordSize(keys[0], e.records[keys[0]])
	r1 := recordSize(keys[1], e.records[keys[1]])
	m := bytes.Clone(img[:off])
	m = append(m, img[off+r0:off+r0+r1]...)
	m = append(m, img[off:off+r0]...)
	m = append(m, img[off+r0+r1:]...)
	if _, err := decodeEnvelope(m); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unsorted accepted: %v", err)
	}
}

func TestValidKeyAndLimits(t *testing.T) {
	e, dek, _ := envelopeFixture(t)
	for _, k := range []key{{"", "a"}, {"a", ""}, {"Gh", "a"}, {"a", "b c"}, {"1a", "b"}} {
		if validKey(k) {
			t.Fatalf("validKey(%q)", k)
		}
		if err := e.put(dek, k, envelopeValue(t, "x")); !errors.Is(err, errInvalidKey) {
			t.Fatalf("put %q: %v", k, err)
		}
	}
	if !validKey(key{"github", "token_1"}) {
		t.Fatal("valid key rejected")
	}
}

func TestCloneIndependent(t *testing.T) {
	e, dek, _ := envelopeFixture(t)
	c := e.clone()
	if err := c.remove(key{"github", "token"}); err != nil {
		t.Fatal(err)
	}
	if err := c.put(dek, key{"new", "x"}, envelopeValue(t, "v")); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.records[key{"github", "token"}]; !ok {
		t.Fatal("clone remove leaked")
	}
	if _, ok := e.records[key{"new", "x"}]; ok {
		t.Fatal("clone put leaked")
	}
	if !e.sealed || c.sealed {
		t.Fatal("sealed state not independent")
	}
}

func TestRekeyFreshDEK(t *testing.T) {
	e, oldDEK, oldImg := envelopeFixture(t)
	next, newDEK, err := e.rekey(oldDEK, envelopeValue(t, "new"))
	if err != nil {
		t.Fatal(err)
	}
	defer newDEK.Destroy()
	if next.sealed {
		t.Fatal("rekeyed envelope published before encode")
	}
	if len(e.records) != 3 {
		t.Fatal("rekey mutated source")
	}
	img, err := next.encode(newDEK)
	if err != nil {
		t.Fatal(err)
	}
	d, err := decodeEnvelope(img)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.unlock(envelopeValue(t, "pass")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("old pass: %v", err)
	}
	if err := d.verify(oldDEK); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("old DEK verified new image: %v", err)
	}
	k, err := d.unlock(envelopeValue(t, "new"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Destroy()
	for kk, want := range map[key]string{{"github", "token"}: "gh", {"cloudflare", "api"}: "cf", {"github", "app"}: "ga"} {
		if _, err := d.open(oldDEK, kk); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("old DEK opened %v: %v", kk, err)
		}
		v, err := d.open(k, kk)
		if err != nil {
			t.Fatal(err)
		}
		if plain(t, v) != want {
			t.Fatalf("%v: wrong plaintext", kk)
		}
		v.Destroy()
	}
	// A retained old snapshot plus old passphrase still yields only the old DEK.
	old, err := decodeEnvelope(oldImg)
	if err != nil {
		t.Fatal(err)
	}
	od, err := old.unlock(envelopeValue(t, "pass"))
	if err != nil {
		t.Fatal(err)
	}
	defer od.Destroy()
	if _, err := d.open(od, key{"github", "token"}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("snapshot DEK opened new record: %v", err)
	}
}

func FuzzDecodeEnvelope(f *testing.F) {
	// Seeds are built once; the fuzz loop itself only parses and never derives keys.
	pass, err := secret.FromBytes([]byte("pass"))
	if err != nil {
		f.Fatal(err)
	}
	defer pass.Destroy()
	e, dek, err := newEnvelope(pass)
	if err != nil {
		f.Fatal(err)
	}
	defer dek.Destroy()
	empty, err := e.encode(dek)
	if err != nil {
		f.Fatal(err)
	}
	v, err := secret.FromBytes([]byte("value"))
	if err != nil {
		f.Fatal(err)
	}
	defer v.Destroy()
	if err := e.put(dek, key{"github", "token"}, v); err != nil {
		f.Fatal(err)
	}
	one, err := e.encode(dek)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(empty)
	f.Add(one)
	f.Add(one[:len(one)-1])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := decodeEnvelope(b)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) || d != nil {
				t.Fatalf("decode error = %v, envelope = %v", err, d)
			}
			return
		}
		if len(b) < minImage || len(b) > maxImage || len(d.records) > maxRecords || !d.sealed {
			t.Fatal("decoded out-of-bounds image")
		}
		// Canonical encoding: an accepted image re-serializes byte-for-byte.
		out := append(d.body(), d.imageNonce[:]...)
		out = append(out, d.imageTag[:]...)
		if !bytes.Equal(out, b) {
			t.Fatal("accepted non-canonical image")
		}
	})
}
