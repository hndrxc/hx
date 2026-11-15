# Security Policy

`hx` is designed with a defense-in-depth, read-only-first architectural posture. Security is treated as an explicit engineering discipline rather than an afterthought.

---

## 1. Supported State & Honest Guarantees

The `hx` repository is currently in **pre-production development** ([Phase 0: Foundations and security](https://github.com/hndrxc/hx/issues/2)).

| Scope | Security Posture & Reality |
| :--- | :--- |
| **Current Default Branch (`main`)** | **Bootstrap / Developer Preview.** Provides Go module setup, Cobra command scaffolding, version metadata reporting, architectural boundary import tests ([F02 / #10](https://github.com/hndrxc/hx/issues/10)), and implemented leaf secret primitives ([S01 / #12](https://github.com/hndrxc/hx/issues/12): redacted values, scoped `Source`/`Handle` interfaces, and TTY-only input; see [Secret Handling & Memory Protection](docs/security/secret-handling.md)). **No production vault, collector implementations, or stable production security guarantees are offered at this stage.** Subsystem runtimes (`hx hub`, `hx tui`, `hx-agent`, `hx-desktop`) exit `1` with not-implemented errors and execute no network listeners, cryptographic services, or storage subsystems. |
| **Planned Foundations** | Planned locked vault lifecycle with local interactive passphrase unlock ([S02 / #14](https://github.com/hndrxc/hx/issues/14)), verifiable audit trail ([S03 / #13](https://github.com/hndrxc/hx/issues/13)), strict egress network allowlists ([S04 / #15](https://github.com/hndrxc/hx/issues/15)), verified TLS pinning ([S05 / #16](https://github.com/hndrxc/hx/issues/16)), and automated security CI gates ([F04 / #20](https://github.com/hndrxc/hx/issues/20)). |
| **Comprehensive Architecture** | Full trust boundaries (TB1–TB13), trust zones, STRIDE analysis, and residual risks are documented in the [Threat Model](docs/security/threat-model.md). |

---

## 2. Reporting a Vulnerability

We take the security of `hx` seriously. If you discover a potential security vulnerability or suspect an architectural flaw that compromises trust boundaries:

### Private Reporting Guidelines

- **Do NOT open a public GitHub issue or post details in public pull requests, discussions, or social channels.**
- **GitHub Private Vulnerability Reporting:** GitHub Private Vulnerability Reporting is currently **disabled** for this repository. Do not attempt to submit reports via GitHub's automated advisory forms until explicitly announced.
- **Reporting Channel Limitation:** No public email or dedicated private reporting channel is currently published on the maintainer's GitHub profile (@hndrxc). Do not invent or send reports to unlisted or guessed email addresses, and do **not** disclose vulnerability details or proof-of-concept exploits in public issues, pull requests, or discussions. If you have an established, verified direct communication channel with @hndrxc, arrange a private disclosure channel there; otherwise, wait until the repository owner publishes or enables a formal private reporting channel before transmitting sensitive details.

### What to Include in a Report

When communicating privately, provide:
1. A clear description of the potential vulnerability, affected code paths, or compromised architectural boundary.
2. Step-by-step instructions or minimal, credential-free reproduction code.
3. An assessment of potential impact (e.g., memory exposure, credential leakage, privilege escalation, bypass of network egress policy).
4. Any proposed remediations or patches.

When received through a verified private channel, reports will be investigated for validation, remediation, and coordinated disclosure.

---

## 3. Strict Rules on Credentials & Secrets

Repository secret handling policies:

1. **Zero Real Secrets in Repository:** Never commit API keys, authentication tokens, TLS private keys, passphrases, seed phrases, or active credentials into Git.
2. **No Secret Fixtures:** Test suites must never use real or historical credentials even for testing. Synthetic test fixtures must use obvious mock values (e.g., `mock-token-00000000`, `test-placeholder-key`) that cannot authenticate against live services.
3. **No Secrets in CLI Arguments or Environment Variables:** In accordance with [ADR-0002](docs/adr/0002-hub-owned-credentials-and-read-only-integrations.md) and [ADR-0009](docs/adr/0009-vault-locked-start-and-unlock.md), credentials are planned to be owned solely by the hub vault and entered via interactive unlock prompts. No environment secrets are permitted at all per repository policy (not merely long-lived variables), and credentials must never be passed via command-line arguments.
