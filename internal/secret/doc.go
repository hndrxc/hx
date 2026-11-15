// Package secret provides redacted, protected secret values and scoped handles
// for the hx system.
//
// All secrets are encapsulated in [Value], which redacts itself across tested fmt
// verbs, serializes to "[REDACTED]" in text/JSON encoders, and refuses
// unmarshaling from text, flags, or configuration. Plaintext is only accessible
// transiently through [Value.Use] callbacks.
//
// Under Linux, secret values are stored in page-aligned memory where mlock and
// MADV_DONTDUMP are requested on a best-effort basis (errors ignored or recorded;
// [Value.Locked] reports false on mlock failure), and zeroed on Destroy. On other
// platforms, buffers degrade to unlocked Go heap memory.
//
// Integration credentials are accessed through [Handle], which binds an
// integration identifier and authorized scopes against a [Source] (such as
// the upcoming S02 hub vault).
//
// Interactive secret entry is provided by [TerminalPrompter], which requires
// a terminal file descriptor with echo disabled via x/term.
//
// For complete security guarantees, architectural invariants, runtime copying
// limits, and ingestion policies, see docs/security/secret-handling.md.
package secret
