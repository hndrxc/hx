package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

const fakeSentinelPlaintext = "hx-s01-sentinel-9f3c2a"

type fakeCall struct {
	Integration IntegrationID
	Scope       Scope
}

type fakeSource struct {
	mu           sync.Mutex
	calls        []fakeCall
	keyMaterial  []byte
	openErr      error
	returnNilVal bool
	returnValErr bool
	secrets      map[string][]byte
}

func newFakeSource(key []byte) *fakeSource {
	km := make([]byte, len(key))
	copy(km, key)
	return &fakeSource{
		keyMaterial: km,
		secrets:     make(map[string][]byte),
	}
}

func (f *fakeSource) Open(_ context.Context, integration IntegrationID, scope Scope) (*Value, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCall{Integration: integration, Scope: scope})

	if f.openErr != nil {
		if f.returnValErr {
			copyBytes := make([]byte, len(f.keyMaterial))
			copy(copyBytes, f.keyMaterial)
			v, err := FromBytes(copyBytes)
			if err != nil {
				return nil, err
			}
			return v, f.openErr
		}
		return nil, f.openErr
	}

	if f.returnNilVal {
		return nil, nil
	}

	key := string(integration) + "/" + string(scope)
	raw, ok := f.secrets[key]
	if !ok {
		if len(f.keyMaterial) > 0 {
			raw = f.keyMaterial
		} else {
			return nil, ErrNotFound
		}
	}

	copyBytes := make([]byte, len(raw))
	copy(copyBytes, raw)
	return FromBytes(copyBytes)
}

func (f *fakeSource) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeSource) lastCall() (fakeCall, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return fakeCall{}, false
	}
	return f.calls[len(f.calls)-1], true
}

func TestHandle_NewHandle_ValidationOrder(t *testing.T) {
	src := newFakeSource([]byte(fakeSentinelPlaintext))

	// 1. nil src must return ErrNoSource even if integration is invalid and scopes are empty.
	_, err := NewHandle(nil, "", "")
	if !errors.Is(err, ErrNoSource) {
		t.Fatalf("expected ErrNoSource for nil src, got: %v", err)
	}

	// 2. Invalid integration must return ErrInvalidIntegration even if scopes are empty.
	_, err = NewHandle(src, "", "")
	if !errors.Is(err, ErrInvalidIntegration) {
		t.Fatalf("expected ErrInvalidIntegration for empty integration, got: %v", err)
	}
	if !strings.Contains(err.Error(), `""`) {
		t.Fatalf("expected error to quote invalid integration, got: %v", err)
	}

	_, err = NewHandle(src, "0invalid", "token")
	if !errors.Is(err, ErrInvalidIntegration) {
		t.Fatalf("expected ErrInvalidIntegration for digit start, got: %v", err)
	}

	// 3. No scopes must return ErrNoScopes.
	_, err = NewHandle(src, "github")
	if !errors.Is(err, ErrNoScopes) {
		t.Fatalf("expected ErrNoScopes for 0 scopes, got: %v", err)
	}

	_, err = NewHandle(src, "github", []Scope{}...)
	if !errors.Is(err, ErrNoScopes) {
		t.Fatalf("expected ErrNoScopes for empty slice, got: %v", err)
	}

	// 4. Invalid scopes must return ErrInvalidScope, reporting the first invalid scope.
	_, err = NewHandle(src, "github", "valid", "bad_scope!")
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("expected ErrInvalidScope for invalid character, got: %v", err)
	}
	if !strings.Contains(err.Error(), `"bad_scope!"`) {
		t.Fatalf("expected error to quote invalid scope, got: %v", err)
	}

	// Ordering of invalid scopes: first invalid in argument order is reported.
	_, err = NewHandle(src, "github", "first!bad", "second!bad")
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("expected ErrInvalidScope, got: %v", err)
	}
	if !strings.Contains(err.Error(), `"first!bad"`) {
		t.Fatalf("expected error to quote first invalid scope, got: %v", err)
	}
}

func TestHandle_ValidName_Boundaries(t *testing.T) {
	src := newFakeSource([]byte(fakeSentinelPlaintext))

	validCases := []string{
		"a",
		"z",
		"github",
		"aws-s3_bucket-01",
		strings.Repeat("a", 64),
	}
	for _, name := range validCases {
		h, err := NewHandle(src, IntegrationID(name), Scope(name))
		if err != nil {
			t.Errorf("expected %q to be valid name, got error: %v", name, err)
			continue
		}
		if h.Integration() != IntegrationID(name) {
			t.Errorf("integration mismatch: got %q, want %q", h.Integration(), name)
		}
	}

	invalidCases := []struct {
		name string
		desc string
	}{
		{"", "empty"},
		{"A", "uppercase first"},
		{"0", "digit first"},
		{"-", "hyphen first"},
		{"_", "underscore first"},
		{"gitHub", "uppercase in middle"},
		{"git hub", "space"},
		{"git/hub", "slash"},
		{"git.hub", "dot"},
		{"git:hub", "colon"},
		{strings.Repeat("a", 65), "exceeds 64 chars"},
	}
	for _, tc := range invalidCases {
		_, err := NewHandle(src, IntegrationID(tc.name), "token")
		if !errors.Is(err, ErrInvalidIntegration) {
			t.Errorf("expected ErrInvalidIntegration for %s (%q), got: %v", tc.desc, tc.name, err)
		}

		_, err = NewHandle(src, "github", Scope(tc.name))
		if !errors.Is(err, ErrInvalidScope) {
			t.Errorf("expected ErrInvalidScope for %s (%q), got: %v", tc.desc, tc.name, err)
		}
	}
}

func TestHandle_NewHandle_DeduplicationAndSorting(t *testing.T) {
	src := newFakeSource([]byte(fakeSentinelPlaintext))

	h, err := NewHandle(src, "github", "write", "read", "admin", "read", "write", "audit")
	if err != nil {
		t.Fatalf("NewHandle failed: %v", err)
	}

	got := h.Scopes()
	want := []Scope{"admin", "audit", "read", "write"}
	if len(got) != len(want) {
		t.Fatalf("scopes length mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("scope[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestHandle_SliceIndependenceRegression(t *testing.T) {
	src := newFakeSource([]byte(fakeSentinelPlaintext))

	// 1. Mutating input slice after NewHandle must not affect Handle's scopes.
	input := []Scope{"write", "read", "admin"}
	h, err := NewHandle(src, "github", input...)
	if err != nil {
		t.Fatalf("NewHandle failed: %v", err)
	}

	input[0] = "corrupted"
	input[1] = "corrupted2"

	got := h.Scopes()
	want := []Scope{"admin", "read", "write"}
	if len(got) != len(want) {
		t.Fatalf("scopes length mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("scope[%d] modified by input mutation: got %q, want %q", i, got[i], want[i])
		}
	}

	// 2. Mutating the slice returned by Scopes() must not affect internal state.
	returned := h.Scopes()
	returned[0] = "corrupted"

	gotAfter := h.Scopes()
	for i := range want {
		if gotAfter[i] != want[i] {
			t.Errorf("scope[%d] modified by returned slice mutation: got %q, want %q", i, gotAfter[i], want[i])
		}
	}
}

func TestHandle_ScopeIsolation(t *testing.T) {
	src := newFakeSource([]byte(fakeSentinelPlaintext))
	src.secrets["github/token"] = []byte("github-secret-token")
	src.secrets["cloudflare/token"] = []byte("cloudflare-secret-token")

	h, err := NewHandle(src, "github", "token")
	if err != nil {
		t.Fatalf("NewHandle failed: %v", err)
	}

	// 1. Undeclared scope must return ErrScopeNotDeclared without calling Source.Open.
	err = h.Use(context.Background(), "repo", func(_ []byte) error {
		t.Fatal("fn should not be called for undeclared scope")
		return nil
	})
	if !errors.Is(err, ErrScopeNotDeclared) {
		t.Fatalf("expected ErrScopeNotDeclared, got: %v", err)
	}
	if src.callCount() != 0 {
		t.Fatalf("Open was called for undeclared scope: callCount=%d", src.callCount())
	}

	// 2. Invalid scope in Use must return ErrInvalidScope without calling Source.Open.
	err = h.Use(context.Background(), "invalid!scope", func(_ []byte) error {
		t.Fatal("fn should not be called for invalid scope")
		return nil
	})
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("expected ErrInvalidScope, got: %v", err)
	}
	if src.callCount() != 0 {
		t.Fatalf("Open was called for invalid scope: callCount=%d", src.callCount())
	}

	// 3. Valid scope calls Open("github", "token") and never retrieves cloudflare secrets.
	var seenPlaintext string
	err = h.Use(context.Background(), "token", func(plaintext []byte) error {
		seenPlaintext = string(plaintext)
		return nil
	})
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}
	if src.callCount() != 1 {
		t.Fatalf("expected exactly 1 Open call, got: %d", src.callCount())
	}
	call, ok := src.lastCall()
	if !ok || call.Integration != "github" || call.Scope != "token" {
		t.Fatalf("unexpected Open call target: %+v", call)
	}
	if seenPlaintext != "github-secret-token" {
		t.Fatalf("expected github secret, got: %q", seenPlaintext)
	}
}

func TestHandle_Use_CancellationNoOpenOrAllocation(t *testing.T) {
	baseline := liveBuffers.Load()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	src := newFakeSource([]byte(fakeSentinelPlaintext))
	h, err := NewHandle(src, "github", "token")
	if err != nil {
		t.Fatalf("NewHandle failed: %v", err)
	}

	err = h.Use(ctx, "token", func(_ []byte) error {
		t.Fatal("fn should not be called on cancelled context")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled unwrapped, got: %v", err)
	}
	if src.callCount() != 0 {
		t.Fatalf("Open was called on cancelled context")
	}
	if cur := liveBuffers.Load(); cur != baseline {
		t.Fatalf("liveBuffers leaked: baseline=%d, current=%d", baseline, cur)
	}
}

func TestHandle_Use_CleanupMatrix(t *testing.T) {
	// Hooks test: restore actual original observer; do not use t.Parallel().
	originalObserver := wipeObserver
	var (
		mu           sync.Mutex
		observedWipe [][]byte
	)
	wipeObserver = func(mem []byte) {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]byte, len(mem))
		copy(cp, mem)
		observedWipe = append(observedWipe, cp)
	}
	t.Cleanup(func() {
		wipeObserver = originalObserver
	})

	assertWipedAndBaseline := func(t *testing.T, name string, baseline int64, wipeCountBefore int) {
		t.Helper()
		if cur := liveBuffers.Load(); cur != baseline {
			t.Errorf("[%s] liveBuffers leaked: baseline=%d, current=%d", name, baseline, cur)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(observedWipe) <= wipeCountBefore {
			t.Errorf("[%s] wipeObserver was not called", name)
			return
		}
		for i := wipeCountBefore; i < len(observedWipe); i++ {
			for j, b := range observedWipe[i] {
				if b != 0 {
					t.Errorf("[%s] wipeObserver saw non-zero byte at index %d: %d", name, j, b)
					break
				}
			}
		}
	}

	src := newFakeSource([]byte(fakeSentinelPlaintext))
	h, err := NewHandle(src, "github", "token")
	if err != nil {
		t.Fatalf("NewHandle failed: %v", err)
	}

	// Case 1: Success
	{
		baseline := liveBuffers.Load()
		wipesBefore := len(observedWipe)
		err := h.Use(context.Background(), "token", func(p []byte) error {
			if string(p) != fakeSentinelPlaintext {
				t.Fatalf("unexpected plaintext: %q", string(p))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("Use returned error on success: %v", err)
		}
		assertWipedAndBaseline(t, "success", baseline, wipesBefore)
	}

	// Case 2: fn returns error
	{
		baseline := liveBuffers.Load()
		wipesBefore := len(observedWipe)
		customErr := errors.New("custom callback error")
		err := h.Use(context.Background(), "token", func(_ []byte) error {
			return customErr
		})
		if !errors.Is(err, customErr) {
			t.Fatalf("expected customErr, got: %v", err)
		}
		assertWipedAndBaseline(t, "fn-error", baseline, wipesBefore)
	}

	// Case 3: fn cancels ctx mid-call and returns ctx.Err()
	{
		baseline := liveBuffers.Load()
		wipesBefore := len(observedWipe)
		ctx, cancel := context.WithCancel(context.Background())
		err := h.Use(ctx, "token", func(_ []byte) error {
			cancel()
			return ctx.Err()
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
		assertWipedAndBaseline(t, "mid-call-cancel", baseline, wipesBefore)
	}

	// Case 4: fn panics
	{
		baseline := liveBuffers.Load()
		wipesBefore := len(observedWipe)
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("expected panic from fn, but none occurred")
				}
				if r != "mid-flight disaster" {
					t.Fatalf("unexpected panic value: %v", r)
				}
			}()
			_ = h.Use(context.Background(), "token", func(_ []byte) error {
				panic("mid-flight disaster")
			})
		}()
		assertWipedAndBaseline(t, "fn-panic", baseline, wipesBefore)
	}
}

func TestHandle_Use_OpenErrorAndNotFound(t *testing.T) {
	// 1. Open returning (v, err) must destroy v and return wrapped error.
	{
		baseline := liveBuffers.Load()
		src := newFakeSource([]byte(fakeSentinelPlaintext))
		src.openErr = errors.New("underlying vault error")
		src.returnValErr = true

		h, err := NewHandle(src, "github", "token")
		if err != nil {
			t.Fatalf("NewHandle failed: %v", err)
		}

		err = h.Use(context.Background(), "token", func(_ []byte) error {
			t.Fatal("fn should not be called when Open fails")
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "underlying vault error") {
			t.Fatalf("expected underlying vault error, got: %v", err)
		}
		if cur := liveBuffers.Load(); cur != baseline {
			t.Fatalf("liveBuffers leaked on (v, err): baseline=%d, current=%d", baseline, cur)
		}
	}

	// 2. Open returning (nil, nil) returns error wrapping ErrNotFound.
	{
		src := newFakeSource([]byte(fakeSentinelPlaintext))
		src.returnNilVal = true

		h, err := NewHandle(src, "github", "token")
		if err != nil {
			t.Fatalf("NewHandle failed: %v", err)
		}

		err = h.Use(context.Background(), "token", func(_ []byte) error {
			t.Fatal("fn should not be called when value is nil")
			return nil
		})
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound for (nil, nil) Open, got: %v", err)
		}
	}

	// 3. Open returning error wrapping ErrLocked is preserved for errors.Is.
	{
		src := newFakeSource([]byte(fakeSentinelPlaintext))
		src.openErr = fmt.Errorf("vault locked status: %w", ErrLocked)

		h, err := NewHandle(src, "github", "token")
		if err != nil {
			t.Fatalf("NewHandle failed: %v", err)
		}

		err = h.Use(context.Background(), "token", func(_ []byte) error {
			t.Fatal("fn should not be called when vault locked")
			return nil
		})
		if !errors.Is(err, ErrLocked) {
			t.Fatalf("expected errors.Is(err, ErrLocked), got: %v", err)
		}
	}

	// 4. Open returning error wrapping ErrNotFound is preserved for errors.Is.
	{
		src := newFakeSource([]byte(fakeSentinelPlaintext))
		src.openErr = fmt.Errorf("secret not located: %w", ErrNotFound)

		h, err := NewHandle(src, "github", "token")
		if err != nil {
			t.Fatalf("NewHandle failed: %v", err)
		}

		err = h.Use(context.Background(), "token", func(_ []byte) error {
			t.Fatal("fn should not be called when secret not found")
			return nil
		})
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected errors.Is(err, ErrNotFound), got: %v", err)
		}
	}
}

type handleContainer struct {
	name string
	val  any
}

func buildHandleContainers(h *Handle) []handleContainer {
	var val Handle
	if h != nil {
		val = *h
	}
	return []handleContainer{
		{name: "*Handle", val: h},
		{name: "Handle", val: val},
		{name: "struct{H Handle}", val: struct{ H Handle }{H: val}},
		{name: "struct{H *Handle}", val: struct{ H *Handle }{H: h}},
		{name: "&struct{Inner struct{H *Handle}}", val: &struct {
			Inner struct{ H *Handle }
		}{Inner: struct{ H *Handle }{H: h}}},
		{name: "[]*Handle", val: []*Handle{h}},
		{name: "map[string]*Handle", val: map[string]*Handle{"handle": h}},
	}
}

func TestHandle_RedactionMatrix(t *testing.T) {
	src := newFakeSource([]byte(fakeSentinelPlaintext))
	h, err := NewHandle(src, "github", "token")
	if err != nil {
		t.Fatalf("NewHandle failed: %v", err)
	}

	encoders := getGeneralEncoders()
	containers := buildHandleContainers(h)

	for _, c := range containers {
		for _, enc := range encoders {
			out, err := enc.fn(c.val)
			if err != nil {
				t.Fatalf("encoder %s failed on container %s: %v", enc.name, c.name, err)
			}
			if strings.Contains(out, fakeSentinelPlaintext) {
				t.Fatalf("encoder %s leaked keyMaterial sentinel in container %s: output %q", enc.name, c.name, out)
			}
		}
	}

	// Exact formatting assertions for single-scope Handle.
	exactWant := "secret.Handle(github: token)"
	if s := fmt.Sprintf("%v", h); s != exactWant {
		t.Fatalf("fmt.Sprintf(%%v, *Handle): got %q, want %q", s, exactWant)
	}
	if s := fmt.Sprintf("%v", *h); s != exactWant {
		t.Fatalf("fmt.Sprintf(%%v, Handle): got %q, want %q", s, exactWant)
	}
	if s := fmt.Sprintf("%+v", h); s != exactWant {
		t.Fatalf("fmt.Sprintf(%%+v, *Handle): got %q, want %q", s, exactWant)
	}
	if s := fmt.Sprintf("%#v", h); s != exactWant {
		t.Fatalf("fmt.Sprintf(%%#v, *Handle): got %q, want %q", s, exactWant)
	}
	if s := fmt.Sprintf("%s", h); s != exactWant {
		t.Fatalf("fmt.Sprintf(%%s, *Handle): got %q, want %q", s, exactWant)
	}
	if s := fmt.Sprintf("%q", h); s != exactWant {
		t.Fatalf("fmt.Sprintf(%%q, *Handle): got %q, want %q", s, exactWant)
	}
	if s := fmt.Sprintf("%x", h); s != exactWant {
		t.Fatalf("fmt.Sprintf(%%x, *Handle): got %q, want %q", s, exactWant)
	}
	if s := fmt.Sprintf("%X", h); s != exactWant {
		t.Fatalf("fmt.Sprintf(%%X, *Handle): got %q, want %q", s, exactWant)
	}
	if s := fmt.Sprintf("%d", h); s != exactWant {
		t.Fatalf("fmt.Sprintf(%%d, *Handle): got %q, want %q", s, exactWant)
	}
	if s := h.String(); s != exactWant {
		t.Fatalf("String(): got %q, want %q", s, exactWant)
	}
	if s := h.GoString(); s != exactWant {
		t.Fatalf("GoString(): got %q, want %q", s, exactWant)
	}

	// JSON output verification.
	jsonBytes, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("json.Marshal(*Handle) failed: %v", err)
	}
	wantJSON := `{"integration":"github","scopes":["token"]}`
	if string(jsonBytes) != wantJSON {
		t.Fatalf("json.Marshal(*Handle): got %q, want %q", string(jsonBytes), wantJSON)
	}

	jsonValBytes, err := json.Marshal(*h)
	if err != nil {
		t.Fatalf("json.Marshal(Handle) failed: %v", err)
	}
	if string(jsonValBytes) != wantJSON {
		t.Fatalf("json.Marshal(Handle): got %q, want %q", string(jsonValBytes), wantJSON)
	}

	// Multi-scope formatting verification.
	hMulti, err := NewHandle(src, "github", "repo", "workflow")
	if err != nil {
		t.Fatalf("NewHandle multi-scope failed: %v", err)
	}
	multiWant := "secret.Handle(github: repo,workflow)"
	if s := fmt.Sprintf("%v", hMulti); s != multiWant {
		t.Fatalf("multi-scope fmt.Sprintf(%%v): got %q, want %q", s, multiWant)
	}

	multiJSONBytes, err := json.Marshal(hMulti)
	if err != nil {
		t.Fatalf("multi-scope json.Marshal failed: %v", err)
	}
	wantMultiJSON := `{"integration":"github","scopes":["repo","workflow"]}`
	if string(multiJSONBytes) != wantMultiJSON {
		t.Fatalf("multi-scope JSON: got %q, want %q", string(multiJSONBytes), wantMultiJSON)
	}

}

func TestHandle_NilReceiverUse(t *testing.T) {
	var h *Handle
	err := h.Use(context.Background(), "token", func(_ []byte) error {
		t.Fatal("fn should not be called on nil Handle")
		return nil
	})
	if !errors.Is(err, ErrScopeNotDeclared) {
		t.Fatalf("expected ErrScopeNotDeclared on nil Handle, got: %v", err)
	}
}

type reflectionConcreteStringSource string

func (reflectionConcreteStringSource) Open(context.Context, IntegrationID, Scope) (*Value, error) {
	return nil, ErrLocked
}

type reflectionConcreteStructSource struct {
	keyMaterial string
	secretBytes []byte
}

func (reflectionConcreteStructSource) Open(context.Context, IntegrationID, Scope) (*Value, error) {
	return nil, ErrLocked
}

func TestHandle_ReflectionExposureRegression(t *testing.T) {
	const sentinel = fakeSentinelPlaintext
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"}

	sources := []struct {
		name string
		src  Source
	}{
		{
			name: "concrete_string_source",
			src:  reflectionConcreteStringSource(sentinel),
		},
		{
			name: "concrete_struct_source_with_string_and_bytes",
			src: reflectionConcreteStructSource{
				keyMaterial: sentinel,
				secretBytes: []byte(sentinel),
			},
		},
		{
			name: "pointer_struct_source_with_string_and_bytes",
			src: &reflectionConcreteStructSource{
				keyMaterial: sentinel,
				secretBytes: []byte(sentinel),
			},
		},
	}

	for _, sc := range sources {
		h, err := NewHandle(sc.src, "github", "token")
		if err != nil {
			t.Fatalf("NewHandle failed for source %s: %v", sc.name, err)
		}

		hiddenContainers := []struct {
			name string
			val  any
		}{
			{
				name: "unexported_handle_value",
				val:  struct{ handle Handle }{handle: *h},
			},
			{
				name: "unexported_handle_pointer",
				val:  struct{ handle *Handle }{handle: h},
			},
			{
				name: "nested_unexported_handle_value",
				val: struct {
					inner struct{ handle Handle }
				}{inner: struct{ handle Handle }{handle: *h}},
			},
			{
				name: "nested_unexported_handle_pointer",
				val: struct {
					inner struct{ handle *Handle }
				}{inner: struct{ handle *Handle }{handle: h}},
			},
		}

		for _, c := range hiddenContainers {
			for _, verb := range verbs {
				out := fmt.Sprintf(verb, c.val)
				if strings.Contains(out, sentinel) {
					t.Fatalf("Source secret exposed for %s under container %s with verb %s: %q",
						sc.name, c.name, verb, out)
				}
			}
		}
	}
}
