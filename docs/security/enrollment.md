# Client enrollment

Scope: the hub enrollment service (`internal/hub/enroll`) is Linux-only. The
client contract (`internal/client/enrollment.go`) is portable code; storage
backends are platform contracts only and none ship yet. No listeners are
deployed by this work.

## Lifecycle

1. **Pinning.** The client pins the hub root CA out-of-band *before* sending
   any enrollment token.
2. **CSR.** The client generates a fresh Ed25519 key locally
   (`NewEnrollmentKey`) and produces a CSR. The private key never leaves the
   client; the hub never holds client private keys.
3. **Approval.** A local operator approves that exact CSR and the target
   device's verified tailnet stable node ID, user ID, and role tag. The local
   adapter authenticates the operator independently of the tailnet lookup.
   Trusted peer values never come from request payloads.
4. **Bind.** Approval yields a single-use bind token with a 5-minute TTL.
   Tokens live in memory only; a hub restart discards every outstanding token
   and the device must be re-approved.
5. **Mint.** The local operator relays the token and CSR through protected IPC.
   The adapter independently refreshes the target device's tailnet identity
   before calling `Enroll`. This bootstrap does not create an unauthenticated
   remote RPC route. Return the public leaf to the device; before storing it, the
   client runs `VerifyIssuedLeaf` with no ambient roots: exact single-DER,
   bounded-size parse; pinned CA is a self-signed Ed25519 CA valid now; leaf is
   non-CA, digital-signature-only, ClientAuth-only, valid now, and signed by
   the pinned CA; leaf key equals the local signer's key.
6. **Renewal.** Renewal issues a new cert for a new key; the old cert is
   invalid immediately (one current record per enrolled ID).
7. **Revocation.** Removes the current record; subsequent use fails closed.
8. **Restart.** Current records are persistent; a hub restart keeps them but
   discards bind tokens (step 4).

If a renewal response is lost, the client does not retry with the old cert
(already invalid): recovery is explicit revoke followed by re-approval. There
is no automatic recovery.

## Local admin

| Operation | Required verification |
|-----------|-----------------------|
| Approve CSR or revoke | Local admin authenticated by protected IPC |
| Bind / mint | Local admin relay, valid token and signed CSR, freshly verified target node/user/tag |
| Renew or use a remote credential | mTLS proof of possession and current WhoIs node/user/tag |

These transport checks are the #19 adapter contract. CSR proof of possession
does not replace mTLS for any remote request after enrollment.

## Roles

| Role | Read | Ingest |
|------|------|--------|
| `RoleRead` (1) | yes | no |
| `RoleIngest` (2) | no | yes |

The device target ID equals the enrolled ID.

## Key custody

- Hub CA/signing keys live in a separate, scoped hub vault.
- Client identity: one bundle per hub scope (hub scope, `crypto.Signer` key,
  leaf DER, pinned hub CA DER). No provider fields; never read from flags,
  env, or plaintext config.
- Linux exception: the private key may be stored as raw PKCS#8 DER only
  inside the designated protected store below, never in config or ambient
  files. This is the sole exception to the no-plaintext rule.
- Linux: private 0700 directory; regular, user-owned 0600 files; no symlinks;
  link count 1; atomic temp-write + fsync + rename + directory fsync. Load
  validates permissions and the certificate/key binding, failing closed.
- Windows: per-user, service-SID-bound Credential Manager/DPAPI user scope; no
  machine scope.
- macOS: Keychain item scoped by app, service, and access group; runtime is
  unsupported per ADR-0005.
- Windows and macOS require the platform secure store; no plaintext fallback.
- Storage adapters receive the key as PKCS#8 DER (e.g. for DPAPI import) in a
  short-lived buffer zeroed after use. `Identity` redacts itself under every
  `fmt` verb and `log/slog`; key and certificate material is never logged.

## Errors and audit

Errors are fixed categories (`ErrDenied`, `ErrExpired`, `ErrUnavailable`,
`ErrCertificate`, `ErrCSR`; client `ErrEnrollment`, `ErrKeyMismatch`) and
support `errors.Is`. Audit uses the existing action categories only:
`client_enrollment` records each lifecycle decision (approval, mint, renewal,
revocation, intent and outcome), but the action does not distinguish the
verb; `api_auth` records each authenticated request. Records carry IDs only —
never tokens, keys, CSRs, or certs.

## Hub signing key and root

- `VaultSigningKey` reads one canonical single-line standard-base64 encoding
  of an Ed25519 PKCS#8 private key from a reserved, PKI-scoped protected vault
  record. It may be entered through an echo-disabled local TTY. It is never
  ingested from command arguments, env, ambient files, or provider scope.
- The public root certificate DER is supplied out of band.

## Registry rollback

Restoring an older registry can revive previously revoked certificates that
have not expired. Operators must preserve the newest registry and the audit
anchor, and must not restore older snapshots; treat any rollback as requiring
root rotation or re-enrollment.

## Limits

No live network, transport, or provider access; no storage backends shipped;
no automatic rollback recovery; no production deployment.
