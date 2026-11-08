# Secret Handling & Memory Protection

Last updated: 2026-11-08

Tracking issue: [Issue #12 (S01)](https://github.com/hndrxc/hx/issues/12)

This document specifies the security guarantees, memory protections, Go runtime limitations, ingestion constraints, and handle access models provided by `internal/secret`.

---

## 1. Guarantees

The `secret.Value` type encapsulates sensitive secret bytes (API tokens, private keys, passwords) and provides strict formatting redaction across standard library and structured encoders:

1. **Formatters (`fmt`)**:
   - `String()` and `GoString()` always return `[REDACTED]`.
   - `Format(f fmt.State, verb rune)` outputs `[REDACTED]` for tested verbs (`%v`, `%+v`, `%#v`, `%s`, `%q`, `%x`, `%X`, `%d`).
   - Values passed to `fmt.Sprint`, `fmt.Sprintln`, `fmt.Printf`, `fmt.Errorf`, `errors.Join`, and `text/template` output `[REDACTED]`.
2. **Encoders (`json`, `slog`, `xml`)**:
   - `MarshalJSON()` serializes to the JSON string `"[REDACTED]"`.
   - `MarshalText()` serializes to `[REDACTED]`.
   - `LogValue()` (`log/slog`) returns `slog.StringValue("[REDACTED]")`.
   - Structs wrapping `*secret.Value` encoded via `encoding/xml` output `[REDACTED]`.
3. **Unexported Struct Fields**:
   - Formatting an unexported `Value` field cannot invoke its methods; its private pointer-based storage keeps plaintext out of reflected output, which contains opaque addresses or formatting diagnostics instead.
4. **Binary & Serialization Refusal**:
   - `Value` does not implement `encoding.BinaryMarshaler` or `gob.GobEncoder`. Attempting to encode a `Value` with `encoding/gob` fails with an encoding error ("no exported fields"), preventing silent leaks into binary streams.
5. **Nil Pointer Handling**:
   - Redaction guarantees apply to non-nil values (both value instances `Value` and initialized pointers `*Value`).
   - A nil `*Value` pointer contains no secret bytes, so no plaintext leakage can occur. When passed directly to encoders, a nil pointer encodes according to standard Go conventions: JSON emits `null`, `fmt` may print `<nil>`, and `log/slog`'s `LogValue` value receiver invocation on a nil pointer triggers a recovered panic diagnostic recorded by slog. Callers should omit or guard optional nil secret attributes when constructing structured log records.

---

## 2. Memory Protection & Platform Tiers

Plaintext buffers are managed by platform-specific allocators (`internal/secret/buffer_linux.go` and `buffer_other.go`):

### Linux (`//go:build linux`)
- **Anonymous Memory Mapping**: Allocations use `golang.org/x/sys/unix.Mmap` (`MAP_PRIVATE | MAP_ANON`) rounded up to the system page size (`os.Getpagesize()`).
- **Memory Locking (`mlock`)**: Memory locking is requested via `unix.Mlock` to prevent swapping to disk. This is best-effort: if `mlock` fails (e.g., due to insufficient `RLIMIT_MEMLOCK` or missing `CAP_IPC_LOCK`), the buffer degrades to unlocked operation and `Locked()` returns `false`, recording the lock error.
- **Core Dump Exclusion (`MADV_DONTDUMP`)**: Core dump exclusion is requested via `unix.Madvise` with `unix.MADV_DONTDUMP` on a best-effort basis (errors are ignored; exclusion cannot be unconditionally promised).
- **Release & Zeroing**: When `Destroy()` is called or buffer release occurs, memory is wiped with `clear()`, kept reachable through `runtime.KeepAlive()` as a compiler liveness barrier, unlocked with `unix.Munlock()` if locked, and unmapped with `unix.Munmap()`.

### Other Operating Systems (`//go:build !linux`)
- On non-Linux platforms (macOS, Windows, BSDs), the buffer falls back to standard Go heap allocations (`make([]byte, n)`).
- Memory locking is unsupported (`Locked()` returns `false`).
- Note: In accordance with [ADR-0005](../adr/0005-supported-platforms-and-build-targets.md), the hub (the sole provider secret holder) is Linux-only. Other OSes compile and run without hardware locking guarantees.

### Lifetime and Wiping
- Every `Destroy()` call wipes the buffer memory and releases OS resources.
- `Destroy()` is idempotent, thread-safe, and nil-safe.
- `Value.Use(fn)` provides a direct, temporary `[]byte` slice of plaintext to the caller callback under a read lock. Callers must not retain, slice-alias, modify, or leak this slice beyond the callback, and must not re-enter `Use`, `Locked`, or call `Destroy` on the same `Value` from within `fn`, as recursive locking on the underlying `sync.RWMutex` can deadlock when a `Destroy` write lock is pending.
- Direct callers of `FromBytes` and `PromptSecret` own the returned `*Value` and are responsible for explicitly calling `Destroy()` (typically via immediate `defer v.Destroy()`); the Go runtime and garbage collector provide no finalizer or automatic wiping guarantees. In contrast, callers of `Handle.Use` do not manage value lifecycles, as `Handle.Use` automatically acquires and destroys the transient `Value` obtained from `Source.Open`.

---

## 3. Go Runtime & Memory Copying Limits

While `internal/secret` minimizes plaintext lifetime and protects its internal buffer, pure Go programs cannot provide hardware-level zero-leak guarantees. As formally recorded in [ADR-0009](../adr/0009-vault-locked-start-and-unlock.md) and the [Threat Model](threat-model.md#residual-risks) (TB7):

> *Go cannot guarantee secret bytes are never copied by runtime/GC.*

Specific known copying vectors and limitations include:

1. **Terminal Input Intermediate Buffer**:
   - Interactive secret input via `TerminalPrompter` relies on `golang.org/x/term.ReadPassword`.
   - `TerminalPrompter` wipes the full capacity of the returned slice, including erased input beyond its logical length. Earlier backing arrays abandoned when `x/term` grows its input slice, and runtime scratch copies, remain outside its control and have no zero-on-free guarantee.
2. **TTY Blocking Nature**:
   - Terminal input reads are blocking system calls (`read` on configured `In` terminal descriptor). They cannot be interrupted by `context.Context` cancellation until a newline or EOF is sent by the terminal.
3. **String Conversions**:
   - Any conversion `string(plaintext)` creates an immutable string on the Go heap that cannot be zeroed or wiped. Callers must strictly work with byte slices or stream encoders.
4. **Third-Party & Standard Libraries**:
   - HTTP client headers (e.g., `Authorization: Bearer <token>`), TLS key exchanges, and API client request payloads allocate copies across standard library buffers, network sockets, and heap objects outside the control of `internal/secret`.
5. **Stack Growth & Garbage Collection**:
   - The Go runtime compiler may copy stack frames during stack growth or move objects during garbage collection cycles.

---

## 4. Ingestion Policy & Source Boundaries

To prevent ambient credential sprawl and accidental persistence, strict ingestion barriers are enforced:

1. **Decoding Refusal**:
   - `Value.UnmarshalJSON([]byte)` and `Value.UnmarshalText([]byte)` return `ErrIngestionForbidden`.
   - `Value` deliberately does not implement `flag.Value`. Secrets cannot be bound to command-line flags.
   - Per [ADR-0002](../adr/0002-hub-owned-credentials-and-read-only-integrations.md), ingesting secrets from environment variables, CLI flags, configuration files, or logs is strictly prohibited.
2. **Terminal-Only Interactive Input**:
   - `TerminalPrompter` validates that `In` refers to a terminal file descriptor using `term.IsTerminal` (not full controlling-terminal verification).
   - Standard input pipes, redirected files, sockets, and non-terminal devices are rejected with `ErrNotTerminal`.
   - Labels must be non-empty, valid UTF-8 without control runes; invalid labels are rejected before output or terminal access.
3. **Constructor Architecture Rule**:
   - Calling `secret.FromBytes` directly constructs a `Value` from raw bytes.
   - Within `internal/secret`, `TerminalPrompter` calls `FromBytes` to encapsulate terminal input.
   - For all external packages, an architecture policy test (`internal/architecture/secret_ingestion_test.go`) enforces that **only** `internal/hub/vault` (to be implemented in S02 #14) is permitted to call `secret.FromBytes`.
   - No production vault currently exists; future S02 implementation will own external secret construction.
4. **Cooperative Boundary Limitation**:
   - The ingestion rule is enforced via Go AST static analysis (`secret_ingestion_test.go`).
   - It is a syntactic, architectural boundary designed to prevent development mistakes and maintain dependency direction. It is **not** a dataflow sandbox, capability security kernel, or hostile-code sandbox.

---

## 5. Scoped Handles & The Source Contract

External components (such as telemetry collectors and providers) must never hold raw secret values directly. Instead, they receive a scoped `secret.Handle`.

```go
type Source interface {
    Open(ctx context.Context, integration IntegrationID, scope Scope) (*Value, error)
}
```

1. **Scope and Integration Binding**:
   - A `Handle` is permanently bound to a single `IntegrationID` and an explicit list of authorized `Scope`s.
   - Both integration IDs and scopes must follow the naming syntax `^[a-z][a-z0-9_-]{0,63}$`.
   - Scopes are deduplicated and sorted at handle construction time.
2. **Cross-Integration & Undeclared Scope Denial**:
   - When `Handle.Use(ctx, scope, fn)` is called, the handle verifies that the requested `scope` is present in its allowed scopes.
   - If the scope is undeclared, `Use` returns `ErrScopeNotDeclared` without invoking `Source.Open`.
   - A handle can only query its own bound `integration` ID, preventing cross-integration token theft.
3. **The S02 Source Contract**:
   - In S02 (#14), the hub vault will implement the `Source` interface. (Note: no production vault implementation exists yet in S01).
   - If a requested secret does not exist, `Source.Open` returns an error wrapping `secret.ErrNotFound`.
   - If the vault is currently locked, `Source.Open` returns an error wrapping `secret.ErrLocked`.
   - On successful `Open`, the returned `*Value` is owned by `Handle.Use`, which ensures `v.Destroy()` is executed via `defer` immediately upon callback completion, error, or panic.
4. **Handle Formatting Redaction**:
   - `Handle` formatters (`String`, `GoString`, `Format`, `MarshalJSON`, `LogValue`) output only the integration name and scope identifiers (e.g., `secret.Handle(github: token)`), never key material or underlying source addresses.
   - When a `Handle` resides in an unexported struct field where reflection-based formatters bypass custom formatting methods, internal indirection keeps the `Source` opaque rather than dumping concrete source contents, including under the tested invalid-verb diagnostics.

---

## 6. Trust Boundary & Threat Model

In accordance with [ADR-0003](../adr/0003-in-process-collector-trust-boundary.md) and the [Threat Model](threat-model.md):

- `internal/secret` operates inside the single hub process.
- It reduces accidental leakage, log contamination, and risk of swap/core dump exposure when OS-level protections (`mlock`, `MADV_DONTDUMP`) succeed, and enforces scope boundaries for cooperative code.
- It makes **no claim** of isolation against hostile code executing within the same Go address space or malicious host-level processes with `ptrace` or root privileges.
