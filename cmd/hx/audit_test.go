package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzParseCheckpoint(f *testing.F) {
	f.Add(uint64(1), []byte("a"), uint8(0), "x")
	f.Add(uint64(0), []byte(""), uint8(1), "")
	f.Add(uint64(1<<63), []byte("z"), uint8(2), "sequence")
	f.Add(uint64(7), []byte("q"), uint8(3), "{}")
	f.Add(uint64(7), []byte("q"), uint8(4), "extra")
	f.Fuzz(func(t *testing.T, seq uint64, hb []byte, mode uint8, extra string) {
		if len(hb) > 64 || len(extra) > 256 {
			t.Skip()
		}
		sum := sha256.Sum256(hb)
		hash := hex.EncodeToString(sum[:])
		valid := fmt.Sprintf(`{"sequence":%d,"hash":%q}`, seq, hash)
		want, ok := parseCheckpoint([]byte(valid))
		if !ok || want.Sequence != seq || want.Hash != hash {
			t.Fatalf("valid checkpoint rejected or altered: %q", valid)
		}
		qe, _ := json.Marshal(extra)
		var bad string
		switch mode % 5 {
		case 0: // duplicate sequence
			bad = fmt.Sprintf(`{"sequence":%d,"hash":%q,"sequence":%d}`, seq, hash, seq)
		case 1: // duplicate hash
			bad = fmt.Sprintf(`{"sequence":%d,"hash":%q,"hash":%s}`, seq, hash, qe)
		case 2: // second object
			bad = valid + valid
		case 3: // trailing garbage token
			bad = valid + " " + string(qe)
		default: // unknown property
			bad = fmt.Sprintf(`{"sequence":%d,"hash":%q,%s:1}`, seq, hash, qe)
		}
		if cp, ok := parseCheckpoint([]byte(bad)); ok {
			t.Fatalf("malformed checkpoint accepted as %+v: %q", cp, bad)
		}
		// Arbitrary raw input: anything accepted must be canonical-stable.
		for _, raw := range []string{extra, valid[:len(valid)/2]} {
			cp, ok := parseCheckpoint([]byte(raw))
			if !ok {
				continue
			}
			canon, err := json.Marshal(cp)
			if err != nil {
				t.Fatal(err)
			}
			again, ok := parseCheckpoint(canon)
			if !ok || again != cp || !checkpointHashRE.MatchString(cp.Hash) {
				t.Fatalf("accepted %q does not roundtrip: %s", raw, canon)
			}
		}
	})
}

const (
	auditZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
	auditFixHash  = "11f55ebd632303695480541fc118f05b1d00c17b56bf560b5c28521751a54ebe"
	auditFixFrame = `{"version":1,"sequence":1,"previous":"` + auditZeroHash +
		`","time":"2026-01-02T03:04:05Z","actor_kind":"operator","actor_id":"00112233445566778899aabbccddeeff",` +
		`"integration_id":"00000000000000000000000000000000","action":"vault_unseal","outcome":"allowed",` +
		`"correlation_id":"ffeeddccbbaa99887766554433221100","hash":"` + auditFixHash + `"}` + "\n"
)

func runAudit(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := newAuditCommand(&out, &errOut)
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

func writeAuditFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAuditVerifyEmptyGenesisUnanchored(t *testing.T) {
	p := writeAuditFile(t, "log", "")
	out, _, err := runAudit(t, "verify", p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "verified sequence=0 hash="+auditZeroHash+"\n") || !strings.Contains(out, "unanchored") {
		t.Fatalf("output: %q", out)
	}
}

func TestAuditVerifyFixtureAnchored(t *testing.T) {
	p := writeAuditFile(t, "log", auditFixFrame)
	cp := writeAuditFile(t, "cp.json", `{"sequence":1,"hash":"`+auditFixHash+`"}`+"\n")
	out, _, err := runAudit(t, "verify", p, "--checkpoint", cp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "verified sequence=1 hash="+auditFixHash+"\n") || !strings.Contains(out, "anchored") || strings.Contains(out, "unanchored") {
		t.Fatalf("output: %q", out)
	}
	out, _, err = runAudit(t, "verify", p)
	if err != nil || !strings.Contains(out, "verified sequence=1 hash="+auditFixHash) || !strings.Contains(out, "unanchored") {
		t.Fatalf("unanchored: %q %v", out, err)
	}
	// Genesis anchor is an exact matching prefix below the head.
	g := writeAuditFile(t, "g.json", `{"sequence":0,"hash":"`+auditZeroHash+`"}`)
	if _, _, err := runAudit(t, "verify", p, "--checkpoint", g); err != nil {
		t.Fatal(err)
	}
}

func TestAuditVerifyFailures(t *testing.T) {
	tampered := strings.Replace(auditFixFrame, `"allowed"`, `"denied"`, 1)
	cases := map[string]string{
		"tampered":  tampered,
		"torn tail": auditFixFrame[:len(auditFixFrame)-20],
		"no LF":     strings.TrimSuffix(auditFixFrame, "\n"),
		"garbage":   "SECRET-PAYLOAD\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := writeAuditFile(t, "log", content)
			out, _, err := runAudit(t, "verify", p)
			if err == nil {
				t.Fatalf("expected failure, output %q", out)
			}
			if strings.Contains(out, "verified") {
				t.Fatalf("must not report verified: %q", out)
			}
			for _, leak := range []string{"SECRET-PAYLOAD", "00112233445566778899aabbccddeeff", "denied"} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("error echoes data: %v", err)
				}
			}
		})
	}
}

func TestAuditVerifyTruncationDetectedByCheckpoint(t *testing.T) {
	p := writeAuditFile(t, "log", "")
	cp := writeAuditFile(t, "cp.json", `{"sequence":1,"hash":"`+auditFixHash+`"}`)
	out, _, err := runAudit(t, "verify", p, "--checkpoint", cp)
	if err == nil || strings.Contains(out, "verified") {
		t.Fatalf("truncated log passed anchored verify: %q %v", out, err)
	}
	// Wrong hash at correct sequence.
	bad := writeAuditFile(t, "bad.json", `{"sequence":1,"hash":"`+strings.Repeat("a", 64)+`"}`)
	full := writeAuditFile(t, "full", auditFixFrame)
	if out, _, err := runAudit(t, "verify", full, "--checkpoint", bad); err == nil || strings.Contains(out, "verified") {
		t.Fatalf("mismatched checkpoint passed: %q %v", out, err)
	}
}

func TestAuditVerifyCheckpointMisuse(t *testing.T) {
	log := writeAuditFile(t, "log", auditFixFrame)
	h := auditFixHash
	cases := map[string]string{
		"unknown key":   `{"sequence":1,"hash":"` + h + `","extra":1}`,
		"duplicate key": `{"sequence":1,"sequence":1,"hash":"` + h + `"}`,
		"trailing":      `{"sequence":1,"hash":"` + h + `"}{"sequence":1,"hash":"` + h + `"}`,
		"trailing junk": `{"sequence":1,"hash":"` + h + `"} x`,
		"missing hash":  `{"sequence":1}`,
		"upper hash":    `{"sequence":1,"hash":"` + strings.ToUpper(h) + `"}`,
		"short hash":    `{"sequence":1,"hash":"abcd"}`,
		"negative seq":  `{"sequence":-1,"hash":"` + h + `"}`,
		"null seq":      `{"sequence":null,"hash":"` + h + `"}`,
		"string seq":    `{"sequence":"1","hash":"` + h + `"}`,
		"array":         `[1]`,
		"empty":         ``,
		"oversized":     `{"sequence":1,"hash":"` + h + `","pad":"` + strings.Repeat("x", 4096) + `"}`,
		"secret junk":   `SECRET-CHECKPOINT`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			cp := writeAuditFile(t, "cp.json", content)
			out, _, err := runAudit(t, "verify", log, "--checkpoint", cp)
			if err == nil {
				t.Fatalf("expected failure, output %q", out)
			}
			if out != "" || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "extra") {
				t.Fatalf("bad output/error: %q %v", out, err)
			}
		})
	}
}

func TestAuditVerifyFileErrors(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "SECRETNAME-missing")
	for _, args := range [][]string{
		{"verify", missing},
		{"verify", dir},
		{"verify", writeAuditFile(t, "log", ""), "--checkpoint", missing},
		{"verify", writeAuditFile(t, "log", ""), "--checkpoint", dir},
		{"verify"},
		{"verify", "a", "b"},
	} {
		out, _, err := runAudit(t, args...)
		if err == nil || out != "" {
			t.Fatalf("%v: expected failure, out %q err %v", args, out, err)
		}
		if strings.Contains(err.Error(), "SECRETNAME") {
			t.Fatalf("error echoes path: %v", err)
		}
	}
}

func TestAuditVerifyEmptyCheckpointFlagRejected(t *testing.T) {
	p := writeAuditFile(t, "log", "")
	out, _, err := runAudit(t, "verify", p, "--checkpoint=")
	if err == nil || out != "" {
		t.Fatalf("explicit empty checkpoint accepted: %q %v", out, err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestAuditVerifyStdoutWriteFailure(t *testing.T) {
	p := writeAuditFile(t, "log", "")
	cmd := newAuditCommand(failWriter{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"verify", p})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err == nil {
		t.Fatal("write failure reported as success")
	}
}

func TestAuditRegisteredOnRoot(t *testing.T) {
	p := writeAuditFile(t, "log", "")
	var out, errOut bytes.Buffer
	if code := execute([]string{"audit", "verify", p}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "verified sequence=0") {
		t.Fatalf("output: %q", out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := execute([]string{"audit", "verify", p, "--checkpoint="}, &out, &errOut); code == 0 {
		t.Fatal("empty checkpoint accepted via root")
	}
}
