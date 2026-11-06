package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hndrxc/hx/internal/buildinfo"
)

func TestHX_Execution(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantOut    string
		wantErr    string
		errCount   int
		wantNoHelp bool
		rejectErr  string
	}{
		{
			name:     "root no args displays help",
			args:     []string{},
			wantCode: 0,
			wantOut:  "Usage:",
		},
		{
			name:     "root help flag",
			args:     []string{"--help"},
			wantCode: 0,
			wantOut:  "Usage:",
		},
		{
			name:     "root version flag",
			args:     []string{"--version"},
			wantCode: 0,
			wantOut:  "hx version " + buildinfo.Version,
		},
		{
			name:     "version subcommand",
			args:     []string{"version"},
			wantCode: 0,
			wantOut:  "hx version " + buildinfo.Version,
		},
		{
			name:       "hub subcommand not implemented",
			args:       []string{"hub"},
			wantCode:   1,
			wantErr:    "not implemented",
			errCount:   1,
			wantNoHelp: true,
		},
		{
			name:     "hub help bypasses runtime",
			args:     []string{"hub", "--help"},
			wantCode: 0,
			wantOut:  "Usage:",
		},
		{
			name:       "tui subcommand not implemented",
			args:       []string{"tui"},
			wantCode:   1,
			wantErr:    "not implemented",
			errCount:   1,
			wantNoHelp: true,
		},
		{
			name:     "tui help bypasses runtime",
			args:     []string{"tui", "--help"},
			wantCode: 0,
			wantOut:  "Usage:",
		},
		{
			name:       "hub rejects extra arguments",
			args:       []string{"hub", "extra"},
			wantCode:   1,
			wantErr:    "Error:",
			errCount:   1,
			wantNoHelp: true,
			rejectErr:  "not implemented",
		},
		{
			name:       "tui rejects extra arguments",
			args:       []string{"tui", "extra"},
			wantCode:   1,
			wantErr:    "Error:",
			errCount:   1,
			wantNoHelp: true,
			rejectErr:  "not implemented",
		},
		{
			name:       "version rejects extra arguments",
			args:       []string{"version", "extra"},
			wantCode:   1,
			wantErr:    "Error:",
			errCount:   1,
			wantNoHelp: true,
		},
		{
			name:       "root rejects extra arguments",
			args:       []string{"extra", "argument"},
			wantCode:   1,
			wantErr:    "Error:",
			errCount:   1,
			wantNoHelp: true,
		},
		{
			name:       "unknown subcommand",
			args:       []string{"unknowncmd"},
			wantCode:   1,
			wantErr:    "unknown command",
			errCount:   1,
			wantNoHelp: true,
		},
		{
			name:       "unknown flag",
			args:       []string{"--invalid-flag"},
			wantCode:   1,
			wantErr:    "unknown flag",
			errCount:   1,
			wantNoHelp: true,
		},
		{
			name:       "disabled completion command",
			args:       []string{"completion"},
			wantCode:   1,
			wantErr:    "unknown command",
			errCount:   1,
			wantNoHelp: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := &bytes.Buffer{}
			errOut := &bytes.Buffer{}

			code := execute(tt.args, out, errOut)
			if code != tt.wantCode {
				t.Fatalf("code = %d, want %d (stdout: %q, stderr: %q)", code, tt.wantCode, out.String(), errOut.String())
			}

			if tt.wantCode == 0 && errOut.Len() > 0 {
				t.Errorf("expected empty stderr on success, got: %q", errOut.String())
			}

			if tt.wantCode != 0 && out.Len() > 0 {
				t.Errorf("expected empty stdout on error, got: %q", out.String())
			}

			if tt.wantOut != "" && !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("stdout %q missing %q", out.String(), tt.wantOut)
			}

			if tt.wantErr != "" && !strings.Contains(errOut.String(), tt.wantErr) {
				t.Errorf("stderr %q missing %q", errOut.String(), tt.wantErr)
			}

			if tt.errCount > 0 {
				if got := strings.Count(errOut.String(), "Error:"); got != tt.errCount {
					t.Errorf("expected %d 'Error:' occurrences, got %d in: %q", tt.errCount, got, errOut.String())
				}
			}

			if tt.wantNoHelp && (strings.Contains(out.String(), "Usage:") || strings.Contains(errOut.String(), "Usage:")) {
				t.Errorf("unexpected usage/help output (stdout: %q, stderr: %q)", out.String(), errOut.String())
			}

			if tt.rejectErr != "" && strings.Contains(errOut.String(), tt.rejectErr) {
				t.Errorf("stderr %q unexpectedly contains rejected runtime error %q", errOut.String(), tt.rejectErr)
			}
		})
	}
}
