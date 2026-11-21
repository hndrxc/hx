//go:build linux

package vault

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "v")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustOpen(t *testing.T, dir string) *disk {
	t.Helper()
	d, err := openDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.close() })
	return d
}

func TestDiskRoundTripAndPerms(t *testing.T) {
	dir := privateDir(t)
	d := mustOpen(t, dir)
	if _, err := d.read(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("read missing: %v", err)
	}
	for _, img := range [][]byte{[]byte("first"), []byte("second-image")} {
		if err := d.write(img); err != nil {
			t.Fatal(err)
		}
		got, err := d.read()
		if err != nil || !bytes.Equal(got, img) {
			t.Fatalf("read = %q, %v", got, err)
		}
	}
	for _, name := range []string{vaultFile, lockFile} {
		st, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode() != 0o600 {
			t.Fatalf("%s mode %v", name, st.Mode())
		}
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), tempPrefix) {
			t.Fatalf("leftover temp %s", e.Name())
		}
	}
}

func TestDiskRejectsBadDir(t *testing.T) {
	loose := privateDir(t)
	os.Chmod(loose, 0o755)
	if d, err := openDisk(loose); err == nil {
		d.close()
		t.Fatal("accepted 0755 dir")
	}
	target := privateDir(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if d, err := openDisk(link); err == nil {
		d.close()
		t.Fatal("accepted symlinked dir")
	}
	if d, err := openDisk(filepath.Join(t.TempDir(), "missing")); err == nil {
		d.close()
		t.Fatal("accepted missing dir")
	}
}

func TestDiskRejectsSymlinkImage(t *testing.T) {
	dir := privateDir(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, vaultFile)); err != nil {
		t.Fatal(err)
	}
	d := mustOpen(t, dir)
	if _, err := d.read(); err == nil {
		t.Fatal("read followed symlink")
	}
	if err := d.write([]byte("new")); err == nil {
		t.Fatal("write replaced symlink")
	}
	if got, _ := os.ReadFile(outside); string(got) != "secret" {
		t.Fatalf("outside modified: %q", got)
	}
}

func TestDiskRejectsSymlinkLock(t *testing.T) {
	dir := privateDir(t)
	outside := filepath.Join(t.TempDir(), "lock")
	os.WriteFile(outside, nil, 0o600)
	if err := os.Symlink(outside, filepath.Join(dir, lockFile)); err != nil {
		t.Fatal(err)
	}
	if d, err := openDisk(dir); err == nil {
		d.close()
		t.Fatal("accepted symlinked lock")
	}
}

func TestDiskRefusedHardlinkLockUnmodified(t *testing.T) {
	dir := privateDir(t)
	outside := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(outside, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outside, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(dir, lockFile)); err != nil {
		t.Skipf("hardlink unsupported: %v", err)
	}
	if d, err := openDisk(dir); err == nil {
		d.close()
		t.Fatal("accepted hardlinked lock")
	}
	fi, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Fatalf("refused lock mode changed to %#o", got)
	}
}

func TestDiskRejectsLooseImage(t *testing.T) {
	dir := privateDir(t)
	p := filepath.Join(dir, vaultFile)
	os.WriteFile(p, []byte("x"), 0o600)
	os.Chmod(p, 0o644)
	d := mustOpen(t, dir)
	if _, err := d.read(); err == nil {
		t.Fatal("read accepted 0644 image")
	}
	if err := d.write([]byte("y")); err == nil {
		t.Fatal("write accepted 0644 target")
	}
}

func TestDiskWriterExclusion(t *testing.T) {
	dir := privateDir(t)
	d := mustOpen(t, dir)
	if d2, err := openDisk(dir); !errors.Is(err, errLocked) {
		if d2 != nil {
			d2.close()
		}
		t.Fatalf("second open: %v", err)
	}
	if err := d.close(); err != nil {
		t.Fatal(err)
	}
	d3, err := openDisk(dir)
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	d3.close()
}

func TestDiskPreRenameFailurePreservesImage(t *testing.T) {
	dir := privateDir(t)
	d := mustOpen(t, dir)
	if err := d.write([]byte("original")); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	d.fsync = func(int) error { return boom }
	if err := d.write([]byte("replacement")); !errors.Is(err, boom) {
		t.Fatalf("write: %v", err)
	}
	got, err := d.read()
	if err != nil || string(got) != "original" {
		t.Fatalf("read = %q, %v", got, err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), tempPrefix) {
			t.Fatalf("leftover temp %s", e.Name())
		}
	}
}
