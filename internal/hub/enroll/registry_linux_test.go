//go:build linux

package enroll

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func testRegistryDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "reg")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testRecord(b byte) record {
	var r record
	r.ID[0] = b
	r.ID[15] = 1
	r.Role = RoleRead
	if b%2 == 0 {
		r.Role = RoleIngest
	}
	tag := "tag:hx-client"
	if r.Role == RoleIngest {
		tag = "tag:hx-agent"
	}
	r.Binding = Binding{NodeID: "node-1", UserID: "user-1", Tag: tag}
	for i := range r.Fingerprint {
		r.Fingerprint[i] = b ^ byte(i)
	}
	return r
}

func testRecords(n int) map[ID]record {
	m := make(map[ID]record, n)
	for i := 1; i <= n; i++ {
		r := testRecord(byte(i))
		m[r.ID] = r
	}
	return m
}

func closeRegistry(t *testing.T, d *registryDisk) {
	t.Helper()
	if err := d.close(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryPersistsAcrossReopen(t *testing.T) {
	dir := testRegistryDir(t)
	d, recs, err := openRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("initial records = %d", len(recs))
	}
	if _, err := os.Stat(filepath.Join(dir, registryFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state created on open: %v", err)
	}
	want := testRecords(3)
	if err := d.save(want); err != nil {
		t.Fatal(err)
	}
	closeRegistry(t, d)

	st, err := os.Stat(filepath.Join(dir, registryFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("state stat %v %v", st, err)
	}
	d, got, err := openRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRegistry(t, d)
	if len(got) != len(want) {
		t.Fatalf("got %d records", len(got))
	}
	for id, r := range want {
		if got[id] != r {
			t.Fatalf("record mismatch for %v", id)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.Name() != registryFile && e.Name() != registryLockFile {
			t.Fatalf("leftover %q", e.Name())
		}
	}
}

func TestRegistryDeterministicEncoding(t *testing.T) {
	a, err := encodeRegistry(testRecords(5))
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		b, err := encodeRegistry(testRecords(5))
		if err != nil || !bytes.Equal(a, b) {
			t.Fatalf("nondeterministic encoding: %v", err)
		}
	}
	if bytes.Contains(a, []byte("\n")) {
		t.Fatal("unexpected newline")
	}
}

func TestRegistryLockExclusive(t *testing.T) {
	dir := testRegistryDir(t)
	d, _, err := openRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := openRegistry(dir); !errors.Is(err, errRegistryLocked) {
		t.Fatalf("second open err = %v", err)
	}
	closeRegistry(t, d)
	d, _, err = openRegistry(dir)
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	closeRegistry(t, d)
}

func TestRegistrySaveRejectsInvalid(t *testing.T) {
	dir := testRegistryDir(t)
	d, _, err := openRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRegistry(t, d)
	r := testRecord(1)
	other := testRecord(2)
	zero := testRecord(3)
	zero.ID = ID{}
	cases := map[string]map[ID]record{
		"key mismatch": {other.ID: r},
		"zero id":      {ID{}: zero},
	}
	for name, recs := range cases {
		if err := d.save(recs); !errors.Is(err, errRegistryInvalid) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	big := make(map[ID]record, maxRegistryEntries+1)
	for i := range maxRegistryEntries + 1 {
		x := testRecord(1)
		x.ID[1], x.ID[2] = byte(i>>8), byte(i)
		big[x.ID] = x
	}
	if err := d.save(big); !errors.Is(err, errRegistryInvalid) {
		t.Fatalf("oversize err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, registryFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid save wrote state")
	}
}

func canonicalImage(t testing.TB) []byte {
	t.Helper()
	raw, err := encodeRegistry(testRecords(2))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func malformedImages(canon []byte) map[string][]byte {
	swapped, _ := encodeRegistry(testRecords(2))
	// Reverse entry order by swapping the two entries' first ID bytes.
	swapped = bytes.Replace(swapped, []byte(`"id":"01`), []byte(`"id":"XX`), 1)
	swapped = bytes.Replace(swapped, []byte(`"id":"02`), []byte(`"id":"01`), 1)
	swapped = bytes.Replace(swapped, []byte(`"id":"XX`), []byte(`"id":"02`), 1)
	return map[string][]byte{
		"empty":         {},
		"null":          []byte("null"),
		"trailing":      append(bytes.Clone(canon), '\n'),
		"trailing doc":  append(bytes.Clone(canon), []byte("{}")...),
		"leading space": append([]byte(" "), canon...),
		"unknown field": bytes.Replace(canon, []byte(`{"version":1,`), []byte(`{"version":1,"x":1,`), 1),
		"dup key":       bytes.Replace(canon, []byte(`{"version":1,`), []byte(`{"version":1,"version":1,`), 1),
		"bad version":   bytes.Replace(canon, []byte(`"version":1`), []byte(`"version":2`), 1),
		"null entries":  []byte(`{"version":1,"entries":null}`),
		"upper hex":     bytes.Replace(canon, []byte(`"id":"01`), []byte(`"id":"0A`), 1),
		"short id":      bytes.Replace(canon, []byte(`"id":"01`), []byte(`"id":"1`), 1),
		"bad role":      bytes.Replace(canon, []byte(`"role":1`), []byte(`"role":9`), 1),
		"role tag skew": bytes.Replace(canon, []byte(`"role":1`), []byte(`"role":2`), 1),
		"unknown tag":   bytes.Replace(canon, []byte(`"tag:hx-client"`), []byte(`"tag:other"`), 1),
		"unsorted":      swapped,
		"dup id":        bytes.Replace(canon, []byte(`"id":"02`), []byte(`"id":"01`), 1),
	}
}

func TestRegistryDecodeRejectsMalformed(t *testing.T) {
	canon := canonicalImage(t)
	if _, err := decodeRegistry(canon); err != nil {
		t.Fatalf("canonical rejected: %v", err)
	}
	for name, raw := range malformedImages(canon) {
		if _, err := decodeRegistry(raw); !errors.Is(err, errRegistryCorrupt) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestRegistryOpenRejectsCorruptState(t *testing.T) {
	canon := canonicalImage(t)
	if _, err := decodeRegistry(canon); err != nil {
		t.Fatalf("canonical rejected: %v", err)
	}
	for name, raw := range malformedImages(canon) {
		if bytes.Equal(raw, canon) {
			t.Fatalf("%s: mutation did not apply", name)
		}
		dir := testRegistryDir(t)
		if err := os.WriteFile(filepath.Join(dir, registryFile), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := openRegistry(dir); !errors.Is(err, errRegistryCorrupt) {
			t.Errorf("%s: err = %v", name, err)
		}
		// The failed open must have released the lock.
		d, _, err := openRegistry(dir)
		if d != nil || !errors.Is(err, errRegistryCorrupt) {
			t.Errorf("%s: retry err = %v", name, err)
		}
	}
}

func TestRegistryRejectsUnsafeStorage(t *testing.T) {
	canon := canonicalImage(t)
	t.Run("dir mode", func(t *testing.T) {
		dir := testRegistryDir(t)
		if err := os.Chmod(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if _, _, err := openRegistry(dir); !errors.Is(err, errRegistryUnsafe) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("dir symlink", func(t *testing.T) {
		dir := testRegistryDir(t)
		link := dir + "-link"
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := openRegistry(link); err == nil {
			t.Fatal("symlinked dir accepted")
		}
	})
	t.Run("state mode", func(t *testing.T) {
		dir := testRegistryDir(t)
		p := filepath.Join(dir, registryFile)
		if err := os.WriteFile(p, canon, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := openRegistry(dir); !errors.Is(err, errRegistryUnsafe) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("state symlink", func(t *testing.T) {
		dir := testRegistryDir(t)
		fake := filepath.Join(t.TempDir(), "fake")
		if err := os.WriteFile(fake, canon, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(fake, filepath.Join(dir, registryFile)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := openRegistry(dir); !errors.Is(err, errRegistryUnsafe) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("state hardlink", func(t *testing.T) {
		dir := testRegistryDir(t)
		p := filepath.Join(dir, registryFile)
		if err := os.WriteFile(p, canon, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(p, filepath.Join(dir, "alias")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := openRegistry(dir); !errors.Is(err, errRegistryUnsafe) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("state directory", func(t *testing.T) {
		dir := testRegistryDir(t)
		if err := os.Mkdir(filepath.Join(dir, registryFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, _, err := openRegistry(dir); err == nil {
			t.Fatal("directory state accepted")
		}
	})
	t.Run("lock symlink", func(t *testing.T) {
		dir := testRegistryDir(t)
		target := filepath.Join(t.TempDir(), "lock")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, registryLockFile)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := openRegistry(dir); err == nil {
			t.Fatal("symlinked lock accepted")
		}
	})
}

func TestRegistrySyncFailureKeepsOldState(t *testing.T) {
	dir := testRegistryDir(t)
	d, _, err := openRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := testRecords(1)
	if err := d.save(old); err != nil {
		t.Fatal(err)
	}
	d.fsync = func(int) error { return unix.EIO }
	if err := d.save(testRecords(3)); err == nil {
		t.Fatal("save succeeded despite sync failure")
	}
	closeRegistry(t, d)
	d, got, err := openRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRegistry(t, d)
	if len(got) != len(old) {
		t.Fatalf("got %d records, want old state", len(got))
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		t.Fatalf("temp not cleaned: %d entries", len(ents))
	}
}

func FuzzEnrollmentRegistry(f *testing.F) {
	canon := canonicalImage(f)
	f.Add(canon)
	empty, err := encodeRegistry(map[ID]record{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(empty)
	for _, raw := range malformedImages(canon) {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		recs, err := decodeRegistry(raw)
		if err != nil {
			if !errors.Is(err, errRegistryCorrupt) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		if len(recs) > maxRegistryEntries {
			t.Fatal("entry cap exceeded")
		}
		again, err := encodeRegistry(recs)
		if err != nil || !bytes.Equal(again, raw) {
			t.Fatalf("accepted non-canonical image: %v", err)
		}
	})
}
