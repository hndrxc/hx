# Hub encrypted vault

Package `internal/hub/vault` keeps integration secrets at rest on the hub. It
implements `secret.Source`, so integrations reach plaintext only through a
scoped `secret.Handle`.

## Storage

- One sealed file, `vault.sealed`, inside an operator-chosen directory that
  must already exist, be owned by the hub user and have mode `0700`. `Open`
  refuses missing or group/world-accessible directories and never creates
  them. Images are private (`0600`) and published by writing a fresh
  temporary file, `fsync`ing it, renaming it over `vault.sealed`, then
  `fsync`ing the directory. A reader sees either the complete old image or
  the complete new image, never a partial one. A failure before the rename
  removes the temporary file and leaves the old image; an error after the
  rename (directory `fsync`) is ambiguous: the new image may be committed.
  A crash can leave a stray `.vault.sealed.tmp-*` residual, which is never
  read as the store.
- The file holds an authenticated manifest plus encrypted records:
  - Key derivation: Argon2id per RFC 9106 with fixed v1 parameters,
    64 MiB memory, 3 passes, parallelism 4, random per-store salt. The
    parameters are fixed for format v1; changing them needs a new version.
  - A random data-encryption key (DEK) encrypts the records. The
    passphrase-derived key only wraps the DEK. Rotation generates a fresh
    DEK, re-encrypts every record under it, wraps it with a key derived from
    the new passphrase and a fresh salt, and publishes the result as one new
    image.
  - AEAD with 24-byte random nonces (XChaCha20-Poly1305 class) for both the
    wrapped DEK and the records. The manifest (format version, KDF
    parameters, salt, wrapped DEK) is authenticated, and every record is bound
    to its integration and scope, so swapping, truncating or editing any byte
    makes unlock fail.
- Any corruption, truncation or wrong passphrase fails closed: the vault stays
  locked, and nothing is rewritten except by an explicit, verified restore.

## Lifecycle and locked state

- `Open(dir, hooks)` always returns a **locked** vault, even when a valid
  `vault.sealed` exists. While locked, `Source.Open` returns an error wrapping
  `secret.ErrLocked`, and `Put`, `Delete`, `Backup` and rotation fail.
- Unlock, initialize, rotate and restore take the passphrase only as a
  `*secret.Value`. The exported entry points are `PromptInitialize`,
  `PromptUnlock`, `PromptRotate` and `PromptRestore`, which accept only a
  concrete `secret.TerminalPrompter`. Pipes, redirects, environment
  variables, flags and configuration files are refused (`secret.ErrNotTerminal`).
- `Put` upserts one integration/scope record and `Delete` removes it. `Lock`
  drops the in-memory keys and records. `Close` locks and releases the
  directory.

## Audit

Every privileged operation is recorded through `audit.Hooks` under its own
action, attributed to the operator actor:

- `vault_initialize`, `vault_unseal` (unlock), `vault_rotate`, `vault_lock`,
  `vault_backup`, `vault_restore`;
- `vault_secret_put` and `vault_secret_delete` for mutations, carrying the
  integration ID;
- `secret_access` for each `Source.Open`.

A grant or publish happens only after its allowed event has been appended:
no plaintext is returned, no key is installed and no image is written unless
that append succeeded. If it fails, the operation is denied and the store on
disk is unchanged. `Lock` is the exception: it erases the keys first and
still erases them if the audit append fails (the error is returned).

Writes record the allowed intent, then publish. If publishing fails, the
vault locks and an error event is appended under the same correlation ID.
After a crash the log may therefore show an allowed intent followed by a
correlated error, or only the allowed intent with no outcome; in the latter
case the on-disk image may be either the old or the new one. Audit events
hold IDs and outcomes only, never secrets, scope values or passphrases. See
[audit-log.md](audit-log.md).

## Backup, restore and recovery

- `Backup` (unlocked only) returns an encrypted snapshot of the current
  store sealed under the current passphrase. It contains no plaintext. It is
  a valid image of the same records, not necessarily byte-identical to
  `vault.sealed` or to an earlier backup.
- Restore requires a locked vault and leaves it locked on success and on
  failure; unlock afterward with the backup's passphrase. It replaces the
  store with the complete snapshot: records absent from the backup are gone.
  The backup must decode and verify with the supplied passphrase, and the
  allowed event must be appended, before anything is written. An invalid
  backup, wrong passphrase or audit failure never overwrites the current
  store. Restore may replace a corrupt current `vault.sealed` (it must still
  be a regular file). A storage error before the rename keeps the prior
  image; one after the rename is ambiguous (see Storage). Restoring is
  repeatable.
- A backup opens only with the passphrase that was current when it was taken.
  **Keep the old passphrase for as long as you keep backups taken under it.**
  Rotation re-encrypts the live store only; existing backups are untouched.
- Restore is an intentional rollback. Anyone who can write the directory and
  knows an older passphrase can roll the vault back to an older snapshot. The
  vault cannot detect that on its own, so restore only trusted backups, and
  keep the audit log's anchor in an independent place so rollback or deletion
  of the audit chain is detectable.
- Durability relies on the file and directory `fsync` described under
  Storage and on the filesystem honouring them. Keep backups.

## Operator interface (handoff to #19)

S02 ships the TTY-only adapters and the vault lifecycle. It does not mount a
CLI command, IPC endpoint or network listener. Per ADR-0009, #19 wires
operator dispatch: the CLI, running on the operator's terminal, prompts for
the passphrase through these TTY-bound adapters. A daemon has no terminal and
cannot call the TTY entry points itself; if the passphrase must reach the
daemon, it may be received only over an authenticated local IPC channel,
never a network listener. No CLI flag, stdin pipe, environment variable or
config option is added to supply passphrases or bypass the TTY requirement.

## Limitations

- Key wiping is best effort. Keys and plaintext live in `secret.Value`
  buffers, which are wiped on `Destroy`/`Lock`, but the Go runtime, the
  KDF/AEAD libraries and `term.ReadPassword` can leave copies in memory
  that never get wiped. Copies can also reach swap or core dumps unless the
  host disables them.
- Anyone holding `vault.sealed` or a backup can guess passphrases offline.
  Argon2id slows guessing, but only a strong passphrase prevents it.
- Locking does not revoke plaintext that callers have already received.
- Any process running as the hub user can read the sealed file, and an
  unlocked hub process is trusted with every record.
