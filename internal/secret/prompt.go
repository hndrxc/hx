package secret

import (
	"context"
	"fmt"
	"io"
	"os"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

// Prompter provides secure interactive secret entry.
type Prompter interface {
	PromptSecret(ctx context.Context, label string) (*Value, error)
}

// TerminalPrompter acquires secret input from an interactive terminal with echo
// disabled.
//
// Limitations and security properties:
//   - The blocking read cannot be interrupted by ctx while waiting for terminal input.
//   - term.ReadPassword uses an intermediate heap buffer that is not wiped by the Go runtime.
//   - TerminalPrompter deliberately offers no environment, flag, file or stdin-pipe fallback.
//
// The returned Value is caller-owned and must be destroyed by calling Destroy.
type TerminalPrompter struct {
	In  *os.File  // must be a terminal; pipes and redirects are rejected
	Out io.Writer // receives only the label and a trailing newline; nil means os.Stderr
}

var isTerminal = term.IsTerminal
var readPassword = term.ReadPassword

func (p TerminalPrompter) PromptSecret(ctx context.Context, label string) (*Value, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if label == "" || !utf8.ValidString(label) {
		return nil, ErrInvalidLabel
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return nil, ErrInvalidLabel
		}
	}

	if p.In == nil || !isTerminal(int(p.In.Fd())) {
		return nil, ErrNotTerminal
	}

	out := p.Out
	if out == nil {
		out = os.Stderr
	}

	if _, err := io.WriteString(out, label+": "); err != nil {
		return nil, fmt.Errorf("secret: write prompt: %w", err)
	}

	b, err := readPassword(int(p.In.Fd()))
	defer clear(b[:cap(b)])
	_, _ = io.WriteString(out, "\n")
	if err != nil {
		return nil, fmt.Errorf("secret: read terminal input: %w", err)
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}

	return FromBytes(b)
}
