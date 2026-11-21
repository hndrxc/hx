package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/hndrxc/hx/internal/hub/audit"
)

// maxCheckpointBytes bounds the checkpoint file read.
const maxCheckpointBytes = 1024

var checkpointHashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// newAuditCommand constructs the audit command group.
func newAuditCommand(out, errOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit log tooling",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.AddCommand(newAuditVerifyCommand(out, errOut))
	return cmd
}

func newAuditVerifyCommand(out, errOut io.Writer) *cobra.Command {
	var checkpointPath string
	cmd := &cobra.Command{
		Use:   "verify LOG",
		Short: "Verify an audit log hash chain (local, read-only)",
		Long: "Verify the hash chain of an audit log file from genesis. Only local files are read.\n" +
			"Without --checkpoint, success proves internal consistency only, not completeness: " +
			"a truncated log still verifies. Provide a trusted checkpoint to detect truncation below it.\n" +
			"The checkpoint is a JSON object {\"sequence\":N,\"hash\":\"HEX\"} and must come from a trusted source.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var anchor *audit.Checkpoint
			if cmd.Flags().Changed("checkpoint") {
				if checkpointPath == "" {
					return errors.New("audit verify: empty checkpoint path")
				}
				cp, err := readCheckpointFile(checkpointPath)
				if err != nil {
					return err
				}
				anchor = &cp
			}
			f, err := os.Open(args[0])
			if err != nil {
				return errors.New("audit verify: cannot open log file")
			}
			defer f.Close()
			st, err := f.Stat()
			if err != nil || !st.Mode().IsRegular() {
				return errors.New("audit verify: log is not a regular file")
			}
			head, err := audit.Verify(f, anchor)
			if err != nil {
				return fmt.Errorf("audit verify: verification failed: %w", err)
			}
			if _, err := fmt.Fprintf(out, "verified sequence=%d hash=%s\n", head.Sequence, head.Hash); err != nil {
				return errors.New("audit verify: cannot write output")
			}
			line := "unanchored: no checkpoint supplied; success does not prove the log is complete\n"
			if anchor != nil {
				line = fmt.Sprintf("anchored: log matches checkpoint sequence=%d\n", anchor.Sequence)
			}
			if _, err := io.WriteString(out, line); err != nil {
				return errors.New("audit verify: cannot write output")
			}
			return nil
		},
	}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.Flags().StringVar(&checkpointPath, "checkpoint", "", "file with trusted checkpoint JSON {\"sequence\":N,\"hash\":\"HEX\"}")
	return cmd
}

func readCheckpointFile(path string) (audit.Checkpoint, error) {
	bad := errors.New("audit verify: invalid checkpoint file")
	f, err := os.Open(path)
	if err != nil {
		return audit.Checkpoint{}, errors.New("audit verify: cannot open checkpoint file")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return audit.Checkpoint{}, bad
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCheckpointBytes+1))
	if err != nil {
		return audit.Checkpoint{}, errors.New("audit verify: cannot read checkpoint file")
	}
	if len(data) > maxCheckpointBytes {
		return audit.Checkpoint{}, errors.New("audit verify: checkpoint file too large")
	}
	cp, ok := parseCheckpoint(data)
	if !ok {
		return audit.Checkpoint{}, bad
	}
	return cp, nil
}

// parseCheckpoint strictly parses one JSON object with exactly the keys
// sequence and hash, each once, and nothing after it except whitespace.
func parseCheckpoint(data []byte) (audit.Checkpoint, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return audit.Checkpoint{}, false
	}
	var cp audit.Checkpoint
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return audit.Checkpoint{}, false
		}
		key, ok := tok.(string)
		if !ok || seen[key] {
			return audit.Checkpoint{}, false
		}
		seen[key] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return audit.Checkpoint{}, false
		}
		switch key {
		case "sequence":
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return audit.Checkpoint{}, false
			}
			if err := json.Unmarshal(raw, &cp.Sequence); err != nil {
				return audit.Checkpoint{}, false
			}
		case "hash":
			if err := json.Unmarshal(raw, &cp.Hash); err != nil {
				return audit.Checkpoint{}, false
			}
		default:
			return audit.Checkpoint{}, false
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return audit.Checkpoint{}, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return audit.Checkpoint{}, false
	}
	if len(seen) != 2 || !checkpointHashRE.MatchString(cp.Hash) {
		return audit.Checkpoint{}, false
	}
	return cp, true
}
