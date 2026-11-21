# Untrusted Text Sanitization

Tracks [#17](https://github.com/hndrxc/hx/issues/17). Provider-controlled strings (repository names, commit messages, VM labels, alert descriptions) are untrusted. `internal/sanitize` is a defensive layer that removes terminal control content and bounds size. It is **not** a substitute for escaping at the output sink.

**Status:** shared sanitizer, client view model, and fixtures. No CLI, TUI, notification, Wails, or hub runtime is wired to them. Revert the S06 change as a unit before adding consumers; no stored state migrates.

## Exported interface

Package `internal/sanitize`:

```go
const (
    MaxInputBytes = 64 << 10 // input beyond this is not examined
    MaxLogBytes   = 4 << 10  // output cap for Log
    MaxLabelBytes = 512      // output cap for Label
)

type Text struct { /* opaque */ }

func (Text) String() string   // sanitized, valid UTF-8
func (Text) Truncated() bool  // true if input or output cap was hit

func Log(string) Text   // multi-line allowed (LF only)
func Label(string) Text // single line
```

`Text` is opaque so callers cannot construct unsanitized values by literal. Clients (CLI, TUI, notifier, desktop bindings) take `Text` for provider-derived fields and call `String()` only at the sink.

`client.NewTextView(sourceID, title, body)` validates the normalized source ID and applies `Label` to the title and `Log` to the body. `SourceID()` retains the exact 1–128 byte ID (ASCII alphanumeric first, then alphanumerics or `._:-`); invalid IDs produce `client.ErrSourceID` without echoing the input. `Title()` and `Body()` return sanitized `Text`. Use the ID as the stable key, even when two titles sanitize to the same text.

Package `internal/testfixture/sanitization`:

```go
type Case struct { Name, Input, Log, Label string }
func Cases() ([]Case, error)
```

Cases are stored as escaped JSON, so no raw control bytes live in the repository. Invalid bytes are given via an `input_hex` field. Fixtures are inert strings (reserved/example hosts only, no real endpoints, nothing executed). `Input` is the raw string; `Log` and `Label` are the expected outputs.

## Behavior

Order of effects: cap input, decode, drop/translate, cap output.

**Caps.** Input is truncated to `MaxInputBytes` before processing. Output is capped at `MaxLogBytes` (Log) or `MaxLabelBytes` (Label). Truncation happens only for the output or input byte cap, never because controls were dropped. When truncated, the fixed UTF-8 ellipsis U+2026 (3 bytes) is appended and counts inside the cap; the marker is reserved only when truncation occurs. Cuts land on rune boundaries, so output is always valid UTF-8.

**Whitespace.**
- Log: LF kept; CRLF becomes LF; U+2028/U+2029 become LF; tab becomes one space.
- Label: LF, CRLF, U+2028, U+2029 each become one space; tab becomes one space.
- Lone CR is dropped in both.

**Dropped.** All other C0 controls, DEL, C1 controls (U+0080–U+009F), and Unicode category Cf, except ZWNJ (U+200C) and ZWJ (U+200D), which are kept for scripts and emoji sequences.

**Malformed UTF-8.** Each invalid byte becomes U+FFFD, one per byte. Exception: a raw C1 byte (0x80–0x9F) is treated as a recognized control (8-bit CSI/OSC/etc.), not as invalid.

**Escape sequences.** Both 7-bit (ESC-introduced) and 8-bit forms (raw C1 byte or its UTF-8 encoding) are recognized and removed entirely:
- CSI.
- OSC, including hyperlinks (OSC 8) and clipboard (OSC 52); terminated by BEL or ST.
- DCS, SOS, PM, APC; terminated by ST.
- Bare ST and generic ESC sequences.
- CAN or SUB cancels an in-progress sequence.
- An unterminated string sequence fails closed: it consumes the remainder of the bounded input.

Only normalized LF remains in multiline output.

## Rendering context contracts

| Sink | Requirement |
|---|---|
| Terminal / TUI / CLI | Print sanitized text only as data fields inside static, program-owned formatting. Never use it in format strings, prompts, window titles, or escape-sequence templates. |
| Notifications | Disable markup and link parsing for the field, or escape for the specific backend at the sink. |
| Wails / web view | Bind as plain strings and render via text nodes (`textContent`, framework text interpolation). Never `innerHTML`, `dangerouslySetInnerHTML`, or `v-html`. |
| Logs | Keep provider text in structured fields, never in the message/format string. Use `Log`/`Label` output as a value. |
| Source ID | Retained and validated separately (strict allowlist). Must never be derived from sanitized text or used as a file path, CSS selector/class, or URL component. |

`<`, `>`, `&`, quotes, and URL text pass through unchanged. They are safe only as plain text and are **not** escaped for HTML, markup, shell, URL, or terminal contexts.

## Limitations

- Not secret redaction; see [secret handling](secret-handling.md). Secrets in provider strings pass through.
- Homoglyphs, bidi-adjacent spoofing, and lookalike text are not detected (Cf bidi controls are dropped, but visual confusables remain).
- Terminal emulator bugs and nonstandard sequences are out of scope; the filter drops everything it recognizes and fails closed on unterminated strings, but cannot guarantee behavior of every emulator.
- No grapheme-cluster or display-width guarantees; byte caps may split a grapheme (never a rune).
- URLs remain visible text and a sink may still auto-link them. Sinks must disable autolinking where clicking is unsafe.
- Truncation hides content; callers should surface `Truncated()` where it matters.

See also: [architecture overview](../architecture/overview.md), [threat model](threat-model.md).
