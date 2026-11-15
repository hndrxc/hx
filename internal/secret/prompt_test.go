package secret

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

func TestPromptSecret_PipeRejected(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	var out bytes.Buffer
	p := TerminalPrompter{
		In:  r,
		Out: &out,
	}

	_, err = p.PromptSecret(context.Background(), "Token")
	if !errors.Is(err, ErrNotTerminal) {
		t.Fatalf("expected ErrNotTerminal, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no output on rejected input, got %q", out.String())
	}
}

func TestPromptSecret_InvalidLabels(t *testing.T) {
	cases := []string{
		"",
		"a\x1b[2J",
		"token\n",
		"token\r",
		"token\t",
		"\x9b2J",         // raw 8-bit C1 CSI (invalid UTF-8 sequence)
		"bad-\xff-label", // invalid UTF-8 byte
		"bad-\xc0\xaf",   // overlong UTF-8
	}

	for _, tc := range cases {
		var out bytes.Buffer
		p := TerminalPrompter{
			In:  os.Stdin,
			Out: &out,
		}

		_, err := p.PromptSecret(context.Background(), tc)
		if !errors.Is(err, ErrInvalidLabel) {
			t.Errorf("label %q: expected ErrInvalidLabel, got %v", tc, err)
		}
		if out.Len() != 0 {
			t.Errorf("label %q: expected no output, got %q", tc, out.String())
		}
	}
}

func TestPromptSecret_ValidUnicodeLabels(t *testing.T) {
	origIsTerm := isTerminal
	origReadPw := readPassword
	t.Cleanup(func() {
		isTerminal = origIsTerm
		readPassword = origReadPw
	})

	isTerminal = func(fd int) bool { return true }
	readPassword = func(fd int) ([]byte, error) {
		return []byte("secret"), nil
	}

	cases := []string{
		"Mot de passe",
		"Clave secreta",
		"密码",
		"パスワード",
		"Ключ",
		"مفتاح",
	}

	for _, label := range cases {
		var out bytes.Buffer
		p := TerminalPrompter{
			In:  os.Stdin,
			Out: &out,
		}

		val, err := p.PromptSecret(context.Background(), label)
		if err != nil {
			t.Fatalf("label %q: unexpected error: %v", label, err)
		}
		if val != nil {
			defer val.Destroy()
		}
		expectedOut := label + ": \n"
		if out.String() != expectedOut {
			t.Fatalf("label %q: expected out %q, got %q", label, expectedOut, out.String())
		}
	}
}

func TestPromptSecret_WipesEntireCapacityOnSuccess(t *testing.T) {
	origIsTerm := isTerminal
	origReadPw := readPassword
	t.Cleanup(func() {
		isTerminal = origIsTerm
		readPassword = origReadPw
	})

	isTerminal = func(fd int) bool { return true }

	// Simulate x/term readPasswordLine backspace behavior:
	// backing array has secret bytes past len(ret).
	backing := []byte("correct-horse-battery-staple-extra-secret")
	logicalLen := len("correct-horse")
	readPassword = func(fd int) ([]byte, error) {
		return backing[:logicalLen:len(backing)], nil
	}

	var out bytes.Buffer
	p := TerminalPrompter{
		In:  os.Stdin,
		Out: &out,
	}

	val, err := p.PromptSecret(context.Background(), "Token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != nil {
		defer val.Destroy()
	}

	err = val.Use(func(plaintext []byte) error {
		if string(plaintext) != "correct-horse" {
			t.Fatalf("unexpected plaintext: %q (expected %q)", string(plaintext), "correct-horse")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("val.Use failed: %v", err)
	}

	for i, b := range backing {
		if b != 0 {
			t.Fatalf("backing[%d] was not zeroed (full capacity wipe expected): %d", i, b)
		}
	}
}

func TestPromptSecret_WipesEntireCapacityOnReadError(t *testing.T) {
	origIsTerm := isTerminal
	origReadPw := readPassword
	t.Cleanup(func() {
		isTerminal = origIsTerm
		readPassword = origReadPw
	})

	isTerminal = func(fd int) bool { return true }

	errBoom := errors.New("read error")
	backing := []byte("error-trailing-secret-residue")
	logicalLen := 5
	readPassword = func(fd int) ([]byte, error) {
		return backing[:logicalLen:len(backing)], errBoom
	}

	var out bytes.Buffer
	p := TerminalPrompter{
		In:  os.Stdin,
		Out: &out,
	}

	val, err := p.PromptSecret(context.Background(), "Token")
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected wrapped errBoom, got %v", err)
	}
	if val != nil {
		defer val.Destroy()
		t.Fatalf("expected nil val on error, got %v", val)
	}

	for i, b := range backing {
		if b != 0 {
			t.Fatalf("backing[%d] was not zeroed on read error: %d", i, b)
		}
	}
}

func TestPromptSecret_WipesEntireCapacityOnEmptyInput(t *testing.T) {
	origIsTerm := isTerminal
	origReadPw := readPassword
	t.Cleanup(func() {
		isTerminal = origIsTerm
		readPassword = origReadPw
	})

	isTerminal = func(fd int) bool { return true }

	// User typed characters then backspaced all of them: len == 0, cap > 0 with typed bytes in backing array.
	backing := []byte("user-typed-then-erased-everything")
	readPassword = func(fd int) ([]byte, error) {
		return backing[:0:len(backing)], nil
	}

	var out bytes.Buffer
	p := TerminalPrompter{
		In:  os.Stdin,
		Out: &out,
	}

	val, err := p.PromptSecret(context.Background(), "Token")
	if !errors.Is(err, ErrEmpty) {
		t.Fatalf("expected ErrEmpty, got %v", err)
	}
	if val != nil {
		defer val.Destroy()
		t.Fatalf("expected nil val on empty, got %v", val)
	}

	for i, b := range backing {
		if b != 0 {
			t.Fatalf("backing[%d] was not zeroed on empty input: %d", i, b)
		}
	}
}

func TestPromptSecret_WipesEntireCapacityOnCancellationDuringRead(t *testing.T) {
	origIsTerm := isTerminal
	origReadPw := readPassword
	t.Cleanup(func() {
		isTerminal = origIsTerm
		readPassword = origReadPw
	})

	isTerminal = func(fd int) bool { return true }

	ctx, cancel := context.WithCancel(context.Background())
	backing := []byte("cancelled-secret-tail-backing-array")
	logicalLen := 9
	readPassword = func(fd int) ([]byte, error) {
		cancel()
		return backing[:logicalLen:len(backing)], nil
	}

	var out bytes.Buffer
	p := TerminalPrompter{
		In:  os.Stdin,
		Out: &out,
	}

	val, err := p.PromptSecret(ctx, "Token")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if val != nil {
		defer val.Destroy()
		t.Fatalf("expected nil val on cancellation, got %v", val)
	}

	for i, b := range backing {
		if b != 0 {
			t.Fatalf("backing[%d] was not zeroed on cancellation: %d", i, b)
		}
	}
}

func TestPromptSecret_PreCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var out bytes.Buffer
	p := TerminalPrompter{
		In:  os.Stdin,
		Out: &out,
	}

	readCalled := false
	origIsTerm := isTerminal
	origReadPw := readPassword
	t.Cleanup(func() {
		isTerminal = origIsTerm
		readPassword = origReadPw
	})

	isTerminal = func(fd int) bool { return true }
	readPassword = func(fd int) ([]byte, error) {
		readCalled = true
		return []byte("secret"), nil
	}

	_, err := p.PromptSecret(ctx, "Token")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if readCalled {
		t.Fatalf("readPassword was called when context was pre-cancelled")
	}
	if out.Len() != 0 {
		t.Fatalf("expected no output when context was pre-cancelled, got %q", out.String())
	}
}

func TestPromptSecret_Success(t *testing.T) {
	origIsTerm := isTerminal
	origReadPw := readPassword
	t.Cleanup(func() {
		isTerminal = origIsTerm
		readPassword = origReadPw
	})

	isTerminal = func(fd int) bool { return true }

	inputSlice := []byte("hx-s01-sentinel-9f3c2a")
	readPassword = func(fd int) ([]byte, error) {
		return inputSlice, nil
	}

	var out bytes.Buffer
	p := TerminalPrompter{
		In:  os.Stdin,
		Out: &out,
	}

	val, err := p.PromptSecret(context.Background(), "Token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer val.Destroy()

	err = val.Use(func(plaintext []byte) error {
		if string(plaintext) != "hx-s01-sentinel-9f3c2a" {
			t.Fatalf("unexpected plaintext: %q", string(plaintext))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("val.Use failed: %v", err)
	}

	for i, b := range inputSlice {
		if b != 0 {
			t.Fatalf("inputSlice[%d] was not zeroed: %d", i, b)
		}
	}

	if out.String() != "Token: \n" {
		t.Fatalf("expected output %q, got %q", "Token: \n", out.String())
	}
}

func TestPromptSecret_ReadError(t *testing.T) {
	origIsTerm := isTerminal
	origReadPw := readPassword
	t.Cleanup(func() {
		isTerminal = origIsTerm
		readPassword = origReadPw
	})

	isTerminal = func(fd int) bool { return true }

	errBoom := errors.New("io error")
	inputSlice := []byte("leftover-secret")
	readPassword = func(fd int) ([]byte, error) {
		return inputSlice, errBoom
	}

	var out bytes.Buffer
	p := TerminalPrompter{
		In:  os.Stdin,
		Out: &out,
	}

	_, err := p.PromptSecret(context.Background(), "Token")
	if !errors.Is(err, errBoom) {
		t.Fatalf("expected wrapped errBoom, got %v", err)
	}

	for i, b := range inputSlice {
		if b != 0 {
			t.Fatalf("inputSlice[%d] was not zeroed on read error: %d", i, b)
		}
	}

	if out.String() != "Token: \n" {
		t.Fatalf("expected output %q, got %q", "Token: \n", out.String())
	}
}

func TestPromptSecret_EmptyInput(t *testing.T) {
	origIsTerm := isTerminal
	origReadPw := readPassword
	t.Cleanup(func() {
		isTerminal = origIsTerm
		readPassword = origReadPw
	})

	isTerminal = func(fd int) bool { return true }
	readPassword = func(fd int) ([]byte, error) {
		return []byte{}, nil
	}

	var out bytes.Buffer
	p := TerminalPrompter{
		In:  os.Stdin,
		Out: &out,
	}

	_, err := p.PromptSecret(context.Background(), "Token")
	if !errors.Is(err, ErrEmpty) {
		t.Fatalf("expected ErrEmpty, got %v", err)
	}

	if out.String() != "Token: \n" {
		t.Fatalf("expected output %q, got %q", "Token: \n", out.String())
	}
}

func TestPromptSecret_CancelledDuringRead(t *testing.T) {
	origIsTerm := isTerminal
	origReadPw := readPassword
	t.Cleanup(func() {
		isTerminal = origIsTerm
		readPassword = origReadPw
	})

	isTerminal = func(fd int) bool { return true }

	ctx, cancel := context.WithCancel(context.Background())
	inputSlice := []byte("secret-during-read")
	readPassword = func(fd int) ([]byte, error) {
		cancel()
		return inputSlice, nil
	}

	baseline := liveBuffers.Load()

	var out bytes.Buffer
	p := TerminalPrompter{
		In:  os.Stdin,
		Out: &out,
	}

	val, err := p.PromptSecret(ctx, "Token")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if val != nil {
		t.Fatalf("expected nil Value on cancellation, got %v", val)
	}

	for i, b := range inputSlice {
		if b != 0 {
			t.Fatalf("inputSlice[%d] was not zeroed on cancellation: %d", i, b)
		}
	}

	if current := liveBuffers.Load(); current != baseline {
		t.Fatalf("expected liveBuffers unchanged (%d), got %d", baseline, current)
	}

	if out.String() != "Token: \n" {
		t.Fatalf("expected output %q, got %q", "Token: \n", out.String())
	}
}
