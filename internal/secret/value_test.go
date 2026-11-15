package secret

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"text/template"
	"time"
)

// Exported container types used across value tests and fuzz testing.

type StructVal struct {
	Token Value
}

type StructPtr struct {
	Token *Value
}

type StructNested struct {
	Inner StructPtr
}

type containerEntry struct {
	name string
	val  any
}

func buildContainers(v *Value) []containerEntry {
	var val Value
	if v != nil {
		val = *v
	}
	return []containerEntry{
		{name: "*Value", val: v},
		{name: "Value", val: val},
		{name: "struct{Token Value}", val: StructVal{Token: val}},
		{name: "struct{Token *Value}", val: StructPtr{Token: v}},
		{name: "&struct{Inner struct{Token *Value}}", val: &StructNested{Inner: StructPtr{Token: v}}},
		{name: "[]*Value", val: []*Value{v}},
		{name: "map[string]*Value", val: map[string]*Value{"token": v}},
	}
}

type encoderEntry struct {
	name string
	fn   func(c any) (string, error)
}

func getGeneralEncoders() []encoderEntry {
	return []encoderEntry{
		{name: "fmt_%v", fn: func(c any) (string, error) { return fmt.Sprintf("%v", c), nil }},
		{name: "fmt_%+v", fn: func(c any) (string, error) { return fmt.Sprintf("%+v", c), nil }},
		{name: "fmt_%#v", fn: func(c any) (string, error) { return fmt.Sprintf("%#v", c), nil }},
		{name: "fmt_%s", fn: func(c any) (string, error) { return fmt.Sprintf("%s", c), nil }},
		{name: "fmt_%q", fn: func(c any) (string, error) { return fmt.Sprintf("%q", c), nil }},
		{name: "fmt_%x", fn: func(c any) (string, error) { return fmt.Sprintf("%x", c), nil }},
		{name: "fmt_%X", fn: func(c any) (string, error) { return fmt.Sprintf("%X", c), nil }},
		{name: "fmt_%d", fn: func(c any) (string, error) { return fmt.Sprintf("%d", c), nil }},
		{name: "fmt_Sprint", fn: func(c any) (string, error) { return fmt.Sprint(c), nil }},
		{name: "fmt_Sprintln", fn: func(c any) (string, error) { return fmt.Sprintln(c), nil }},
		{name: "fmt_Errorf_v", fn: func(c any) (string, error) { return fmt.Errorf("wrap: %v", c).Error(), nil }},
		{name: "fmt_Errorf_w", fn: func(c any) (string, error) { return fmt.Errorf("wrap: %w", fmt.Errorf("inner %v", c)).Error(), nil }},
		{name: "errors_Join", fn: func(c any) (string, error) {
			return errors.Join(fmt.Errorf("e1: %v", c), fmt.Errorf("e2: %v", c)).Error(), nil
		}},
		{name: "json_Marshal", fn: func(c any) (string, error) { b, err := json.Marshal(c); return string(b), err }},
		{name: "json_MarshalIndent", fn: func(c any) (string, error) { b, err := json.MarshalIndent(c, "", "  "); return string(b), err }},
		{
			name: "text_template",
			fn: func(c any) (string, error) {
				tmpl, err := template.New("t").Parse("{{.}}")
				if err != nil {
					return "", err
				}
				var buf bytes.Buffer
				err = tmpl.Execute(&buf, c)
				return buf.String(), err
			},
		},
		{
			name: "log_Printf",
			fn: func(c any) (string, error) {
				var buf bytes.Buffer
				l := log.New(&buf, "", 0)
				l.Printf("%v", c)
				return buf.String(), nil
			},
		},
		{
			name: "slog_Text",
			fn: func(c any) (string, error) {
				var buf bytes.Buffer
				opts := &slog.HandlerOptions{
					ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
						if a.Key == slog.TimeKey {
							return slog.Attr{}
						}
						return a
					},
				}
				logger := slog.New(slog.NewTextHandler(&buf, opts))
				logger.Info("msg", slog.Any("token", c))
				return buf.String(), nil
			},
		},
		{
			name: "slog_JSON",
			fn: func(c any) (string, error) {
				var buf bytes.Buffer
				opts := &slog.HandlerOptions{
					ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
						if a.Key == slog.TimeKey {
							return slog.Attr{}
						}
						return a
					},
				}
				logger := slog.New(slog.NewJSONHandler(&buf, opts))
				logger.Info("msg", slog.Any("token", c))
				return buf.String(), nil
			},
		},
	}
}

func encodeXML(v *Value) (string, error) {
	b, err := xml.Marshal(StructPtr{Token: v})
	return string(b), err
}

func TestValue_RedactionMatrix(t *testing.T) {
	const sentinel = "hx-s01-sentinel-9f3c2a"
	v, err := FromBytes([]byte(sentinel))
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	defer v.Destroy()

	containers := buildContainers(v)
	encoders := getGeneralEncoders()

	for _, c := range containers {
		for _, enc := range encoders {
			out, err := enc.fn(c.val)
			if err != nil {
				t.Fatalf("encoder %s failed on container %s: %v", enc.name, c.name, err)
			}
			if strings.Contains(out, sentinel) {
				t.Fatalf("encoder %s leaked sentinel in container %s: output %q", enc.name, c.name, out)
			}
			if !strings.Contains(out, Redacted) {
				t.Fatalf("encoder %s did not contain %q for container %s: output %q", enc.name, Redacted, c.name, out)
			}
		}
	}

	// xml.Marshal of struct{Token *Value} (StructPtr)
	xmlOut, err := encodeXML(v)
	if err != nil {
		t.Fatalf("encodeXML failed: %v", err)
	}
	if strings.Contains(xmlOut, sentinel) {
		t.Fatalf("xml.Marshal leaked sentinel: %q", xmlOut)
	}
	if !strings.Contains(xmlOut, Redacted) {
		t.Fatalf("xml.Marshal did not contain %q: %q", Redacted, xmlOut)
	}

	// Nil containers: must not contain sentinel, and no panic.
	nilContainers := []containerEntry{
		{name: "(*Value)(nil)", val: (*Value)(nil)},
		{name: "struct{Token *Value}{Token: nil}", val: StructPtr{Token: nil}},
	}
	for _, c := range nilContainers {
		for _, enc := range encoders {
			out, err := enc.fn(c.val)
			if err != nil {
				t.Fatalf("encoder %s failed on nil container %s: %v", enc.name, c.name, err)
			}
			if strings.Contains(out, sentinel) {
				t.Fatalf("encoder %s leaked sentinel on nil container %s: %q", enc.name, c.name, out)
			}
		}
	}
}

func TestValue_UnexportedField(t *testing.T) {
	const sentinel = "hx-s01-sentinel-9f3c2a"
	v, err := FromBytes([]byte(sentinel))
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	defer v.Destroy()

	type unexportedContainer struct {
		token *Value
	}
	c := unexportedContainer{token: v}
	out := fmt.Sprintf("%+v", c)
	if strings.Contains(out, sentinel) {
		t.Fatalf("unexported field format leaked sentinel: %q", out)
	}
}

func TestValue_GobRefusal(t *testing.T) {
	const sentinel = "hx-s01-sentinel-9f3c2a"
	v, err := FromBytes([]byte(sentinel))
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	defer v.Destroy()

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(StructPtr{Token: v})
	if err == nil {
		t.Fatalf("expected gob.Encode to fail, but it succeeded")
	}
	if strings.Contains(buf.String(), sentinel) {
		t.Fatalf("gob buffer contains sentinel after failed encode: %q", buf.String())
	}
}

func TestValue_IngestionForbidden(t *testing.T) {
	var target StructVal
	jsonErr := json.Unmarshal([]byte(`{"Token":"x"}`), &target)
	if jsonErr == nil {
		t.Fatalf("expected json.Unmarshal to fail, got nil")
	}
	if !errors.Is(jsonErr, ErrIngestionForbidden) {
		t.Fatalf("expected json.Unmarshal error to wrap ErrIngestionForbidden, got: %v", jsonErr)
	}

	var flagVal Value
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.TextVar(&flagVal, "token", Value{}, "secret token")
	flagErr := fs.Parse([]string{"-token=abc"})
	if flagErr == nil {
		t.Fatalf("expected fs.Parse with flag.TextVar to fail, got nil")
	}

	var v Value
	if err := v.UnmarshalJSON([]byte("test")); !errors.Is(err, ErrIngestionForbidden) {
		t.Fatalf("expected UnmarshalJSON to return ErrIngestionForbidden, got: %v", err)
	}
	if err := v.UnmarshalText([]byte("test")); !errors.Is(err, ErrIngestionForbidden) {
		t.Fatalf("expected UnmarshalText to return ErrIngestionForbidden, got: %v", err)
	}
}

func TestValue_FromBytes_InputClearing(t *testing.T) {
	// Success case
	input := []byte("temporary-secret-data")
	v, err := FromBytes(input)
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	defer v.Destroy()

	for i, b := range input {
		if b != 0 {
			t.Fatalf("expected input[%d] == 0 on success, got %d", i, b)
		}
	}

	// ErrEmpty case
	emptyInput := make([]byte, 0, 16)
	_, err = FromBytes(emptyInput)
	if !errors.Is(err, ErrEmpty) {
		t.Fatalf("expected ErrEmpty, got %v", err)
	}

	// ErrTooLarge case
	tooLarge := make([]byte, MaxSize+1)
	for i := range tooLarge {
		tooLarge[i] = 'X'
	}
	_, err = FromBytes(tooLarge)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
	for i, b := range tooLarge {
		if b != 0 {
			t.Fatalf("expected tooLarge[%d] == 0 on ErrTooLarge, got %d", i, b)
		}
	}
}

func TestValue_Use_Lifecycle(t *testing.T) {
	raw := []byte("plaintext-use-test")
	v, err := FromBytes(raw)
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	defer v.Destroy()

	// Direct view of plaintext
	var viewed []byte
	err = v.Use(func(p []byte) error {
		viewed = make([]byte, len(p))
		copy(viewed, p)
		return nil
	})
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}
	if string(viewed) != "plaintext-use-test" {
		t.Fatalf("expected viewed %q, got %q", "plaintext-use-test", string(viewed))
	}

	// Callback error returned unchanged
	customErr := errors.New("custom callback error")
	gotErr := v.Use(func(p []byte) error {
		return customErr
	})
	if gotErr != customErr {
		t.Fatalf("expected callback error %v, got %v", customErr, gotErr)
	}

	// Destroy and post-destroy Use
	v.Destroy()
	if err := v.Use(func(p []byte) error { return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("expected ErrDestroyed after Destroy, got %v", err)
	}

	// Second Destroy is an idempotent no-op
	v.Destroy()

	// Zero Value{} Use returns ErrDestroyed
	var zeroVal Value
	if err := zeroVal.Use(func(p []byte) error { return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("expected ErrDestroyed for zero Value, got %v", err)
	}
	zeroVal.Destroy()

	// Nil *Value Use returns ErrDestroyed
	var nilVal *Value
	if err := nilVal.Use(func(p []byte) error { return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("expected ErrDestroyed for nil *Value, got %v", err)
	}
	nilVal.Destroy()
}

func TestValue_WipeObserverAndLiveBuffers(t *testing.T) {
	baseline := liveBuffers.Load()

	originalObserver := wipeObserver
	var observedMem []byte
	wipeObserver = func(mem []byte) {
		observedMem = make([]byte, len(mem))
		copy(observedMem, mem)
	}
	t.Cleanup(func() {
		wipeObserver = originalObserver
	})

	v, err := FromBytes([]byte("wipe-observation-test"))
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	if got := liveBuffers.Load(); got != baseline+1 {
		v.Destroy()
		t.Fatalf("expected liveBuffers %d, got %d", baseline+1, got)
	}

	v.Destroy()

	if got := liveBuffers.Load(); got != baseline {
		t.Fatalf("expected liveBuffers to return to baseline %d, got %d", baseline, got)
	}

	if len(observedMem) == 0 {
		t.Fatalf("wipeObserver was not invoked")
	}
	for i, b := range observedMem {
		if b != 0 {
			t.Fatalf("wipeObserver saw non-zero byte at index %d: %d", i, b)
		}
	}
}

func TestValue_PlatformLocking(t *testing.T) {
	v, err := FromBytes([]byte("platform-lock-test"))
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	defer v.Destroy()

	if runtime.GOOS == "linux" {
		if !v.Locked() {
			if v.s != nil && v.s.buf != nil && (errors.Is(v.s.buf.lockErr, syscall.EPERM) || errors.Is(v.s.buf.lockErr, syscall.ENOMEM)) {
				t.Skipf("skipping mlock assertion due to system limit: %v", v.s.buf.lockErr)
			}
			t.Fatalf("expected fresh Value to be locked on linux, got locked=false, lockErr: %v", v.s.buf.lockErr)
		}
	} else {
		if v.Locked() {
			t.Fatalf("expected locked=false on !linux, got true")
		}
	}

	v.Destroy()
	if v.Locked() {
		t.Fatalf("expected locked=false after Destroy, got true")
	}

	var nilV *Value
	if nilV.Locked() {
		t.Fatalf("expected nil *Value to report locked=false")
	}
	var zeroV Value
	if zeroV.Locked() {
		t.Fatalf("expected zero Value to report locked=false")
	}
}

func TestValue_SharedStateCopyAndConcurrentUseDestroy(t *testing.T) {
	// Shared-state copy test
	v1, err := FromBytes([]byte("shared-state-copy-secret"))
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	v2 := *v1 // shallow copy shares state pointer s

	// Calling Destroy on copy destroys the state for both
	v2.Destroy()

	if err := v1.Use(func(p []byte) error { return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("expected v1.Use to return ErrDestroyed after v2.Destroy, got %v", err)
	}
	if err := v2.Use(func(p []byte) error { return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("expected v2.Use to return ErrDestroyed after v2.Destroy, got %v", err)
	}

	// Concurrent Use vs Destroy test
	v, err := FromBytes([]byte("concurrent-race-secret"))
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	for range goroutines {
		go func() {
			defer wg.Done()
			for range 200 {
				err := v.Use(func(p []byte) error {
					if string(p) != "concurrent-race-secret" {
						return errors.New("corrupted plaintext")
					}
					return nil
				})
				if err != nil && !errors.Is(err, ErrDestroyed) {
					t.Errorf("unexpected Use error: %v", err)
					return
				}
			}
		}()
	}

	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Millisecond)
		v.Destroy()
	}()

	wg.Wait()

	if err := v.Use(func(p []byte) error { return nil }); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("expected v.Use to return ErrDestroyed post-concurrency, got %v", err)
	}
}
