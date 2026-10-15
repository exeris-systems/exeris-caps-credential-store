# exeris-caps-credential-store

Password credentials as an Exeris capability. It provides `CredentialStore` (create a credential, authenticate, change a password, with a lockout after repeated failures), `AccountVerification` (single-use, expiring tokens that verify a login's address) and `CredentialRecovery` (password-reset tokens and their consumption). Tokens are stored hashed.

Status: proof of concept, built against `exeris-kernel` 0.13.0-SNAPSHOT. The API is not stable and no artefact has been published.

## Where it sits

- **Layer:** Layer 5 — Domain primitive (identity), in the Tier 2 capability map of [`high-level-architecture.md`](https://github.com/exeris-systems/exeris-docs/blob/main/high-level-architecture.md) §3.2.
- **Depends on:** `exeris-kernel-spi`, `exeris-sdk-composition-lifecycle` and, optionally, `exeris-caps-audit-trail` (see "What is optional" below).
- **Provides** (`@Provides`, all version 0.1.0): `CredentialStore`, `AccountVerification`, `CredentialRecovery`.
- **Requires** (`@Requires`, each declared `optional = true` because the capability graph resolves edges between capability modules only, and none of these is one; see "What is optional" below): `eu.exeris.caps.credentialstore.spi.NotificationDispatcher`, `eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder`, `eu.exeris.kernel.spi.persistence.TransactionalExecutor`, `eu.exeris.caps.credentialstore.spi.SessionStore`, `eu.exeris.caps.audittrail.api.AuditLogSink`.
- **Wall (ADR-055):** `eu.exeris.caps.credentialstore.api` is the cross-cap surface; `eu.exeris.caps.credentialstore.internal` is private, and a sibling cap reaching into it fails the build. No Spring, servlet, Netty or reactive type may appear (ADR-006).

Behaviour worth knowing before composing it:

- **A password is written only with proof.** `createCredential` inserts a credential for a subject and a login identifier that have none, and throws `CredentialAlreadyExistsException` otherwise; `changePassword` needs the current password; `CredentialRecovery.consumeReset` needs a single-use reset token. Nothing sets the password of an existing credential without one of those, so a registration or an invitation for an address that already has an account cannot replace its password. The composing SKU answers `CredentialAlreadyExistsException` exactly as it answers a successful registration.
- **The login identifier is the address.** It is stored with the credential (NFC, stripped, lower-cased, unique; an identifier containing whitespace, control, Unicode format or space-separator characters is refused), and verification and reset tokens are sent only to it, never to an address the caller supplies. `issueVerification` and `requestReset` take the login and return without issuing anything for an unknown login, a verified account or a request inside the cooldown, so the caller answers every request alike. A failure of the `NotificationDispatcher` is logged and not thrown, so it does not tell a known account from an unknown one; the user may ask again after the cooldown. Response time is not constant and is not a secret.
- **Sign-in is gated on verification.** A credential is created unverified. `authenticate` and `verifyCredential` return `SUCCESS`, `INVALID`, `LOCKED` or `UNVERIFIED`. An unknown login and a wrong password are both `INVALID` and both run the key derivation. `UNVERIFIED` is reported only after the password matched, so it tells nothing to a caller who does not know the password. `LOCKED` can only happen to an existing account, so a caller that must not confirm an account exists presents it as `INVALID`. Consuming a reset token also verifies the address, since the token reached it.
- **Lockout is atomic.** Each password check reserves an attempt with one conditional `UPDATE` before the derivation runs, so concurrent guesses cannot exceed the limit. Failures count within a window. `LockoutPolicy.fromConfig` and `TokenPolicy.fromConfig` read the limits from kernel configuration (`caps.credential-store.lockout.max-attempts`, `.failure-window-seconds`, `.duration-seconds`; `caps.credential-store.token.verification-validity-seconds`, `.reset-validity-seconds`, `.issue-cooldown-seconds`); the defaults are 5 failures in 15 minutes, a 15-minute lockout, 24-hour verification and 15-minute reset tokens, and a 60-second cooldown. A duration above 3650 days is refused.
- **Hashing goes through the kernel `KernelPasswordEncoder`**, whose contract requires a constant-time comparison. The SKU supplies the implementation (ADR-099 obligation 6), normally the community `Argon2idPasswordEncoder`; the cap names no driver class and has no fallback encoder. An encoder that also implements `RehashablePasswordEncoder` has a legacy hash re-encoded on the next successful sign-in.
- **Storage is PostgreSQL through the kernel Persistence SPI.** The composing SKU builds the module with its wiring constructor (a `TransactionalExecutor`, a `KernelPasswordEncoder`, a `NotificationDispatcher`, a `LockoutPolicy`, a `TokenPolicy` and a `PasswordPolicy`, and optionally a `SessionStore` and an `AuditRecorder`) and applies `CredentialStoreModule.MIGRATIONS` before the first call; nothing applies them automatically. The instance the composition conductor creates through the no-arg constructor runs the lifecycle hooks only and hands out no service. There is no in-memory store.
- **The tables are deployment-global.** A subject has one credential whatever tenants it belongs to (ADR-099 obligation 10), so the tables carry no `tenant_id` and no row-level-security policy. Tenant isolation (ADR-012) belongs to membership and role grants, which the multi-tenancy and rbac-policy capabilities own.
- **Password length.** `PasswordPolicy` (`caps.credential-store.password.min-length`, `.max-length`; default 8 and 128 UTF-16 code units) is checked before any key derivation: the minimum for a password being set, the maximum for every password the cap is handed, so a stored credential whose password is longer than the maximum can no longer authenticate (lowering the maximum, or importing hashes of longer passwords, needs a reset path for those subjects).
- **Sessions are revoked before the password is written.** `changePassword` and `consumeReset` call `SessionStore.revokeAllForSubject` first; if it throws, the call fails with the password, the token version and the reset token untouched. After the commit they revoke once more for a session opened in between; that second sweep is logged, not thrown, and the incremented token version is what refuses the stragglers. The session store has its own unit of work and cannot join the credential transaction.
- **Audit comes after the commit and cannot fail the call.** An exception from the `AuditRecorder` is logged and swallowed; the event is lost, the operation stands.
- **`getTokenVersion` is an `OptionalLong`**, empty for a subject without a credential, so an unknown subject cannot match a token's version.
- `clearLockout` carries no authorisation; the caller decides who may unlock an account.
- Delivering a token, revoking sessions and recording audit events go through interfaces this cap declares itself (`spi.NotificationDispatcher`, `spi.SessionStore`, `spi.AuditRecorder`).

### What is optional

| Dependency | In the capability graph | In the wiring constructor | On the class path |
|---|---|---|---|
| `TransactionalExecutor`, `KernelPasswordEncoder`, `NotificationDispatcher` | `optional = true` | required (`null` is refused) | required |
| `SessionStore` | `optional = true` | may be `null`: no revocation | required (the interface is in this jar) |
| Audit | `optional = true` | `AuditRecorder` may be `null`: no events | the `exeris-caps-audit-trail` jar is optional |

No signature of `CredentialStoreModule` names an audit-trail type. A composition with that capability adapts its sink with `spi.AuditLogSinkRecorder`, the only class here that names one; a composition without the jar never loads it.

## Build & test

Requires JDK 25 and Maven 3.9+.

```bash
mvn compile -Dexeris.codegen.skip=true   # pass 1 — the processor writes capability metadata
mvn verify                               # pass 2 — generate cap-manifest.json, validate the graph, scan the Wall
```

`PostgresCredentialRepositoryLiveIT` runs the lockout reservation, the cooldown and the token statements against a real PostgreSQL. It uses `EXERIS_TEST_PG_URL` (a JDBC URL), `EXERIS_TEST_PG_USER` and `EXERIS_TEST_PG_PASSWORD` (or the `exeris.test.pg.url`, `.user` and `.password` system properties) when all three are set, and otherwise starts a `postgres:16` container through Testcontainers, which needs Docker. It creates and drops its own schema. With neither it is skipped, unless `EXERIS_REQUIRE_LIVE_PG=true`, which makes it fail; the CI workflow sets that and checks the report.

Both passes are needed after a `clean`: `exeris:generate` runs before `compile`, and `compile` is when the processor writes the metadata it reads. `src/main/generated/java/cap-manifest.json` is committed, so a clean `git status` after `mvn verify` shows the manifest matches the declaration.

`exeris-sdk` 0.12.0 and `exeris-tooling` 0.10.0 resolve from Maven Central, and `exeris-kernel` 0.13.0-SNAPSHOT is resolved from GitHub Packages, which needs a token with `read:packages`; the sibling `exeris-caps-service-boundary-core` and `exeris-caps-audit-trail` are built from source first. [`.github/workflows/build.yml`](.github/workflows/build.yml) is the exact sequence, and [`.github/maven-settings.xml`](.github/maven-settings.xml) the repository configuration it uses.

## Documentation

- [`AGENTS.md`](AGENTS.md) — the repository's operating contract and invariants.
- [`ROADMAP.md`](ROADMAP.md) — what the proof of concept does not cover.
- [Capability Author Guide](https://github.com/exeris-systems/exeris-docs/blob/main/cap-author-guide.md) — how a cap declares `@CapabilityModule`, `@Provides`, `@Requires` and `@CapabilityLifecycle`.
- [Capability licence registry](https://github.com/exeris-systems/exeris-docs/blob/main/cap-license-registry.md) — the licence value of every cap.

Where they disagree, the ADRs below and the HLA outrank this README.

## Governing ADRs

- [ADR-006](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-006-spring-free-kernel-boundary.md) — Spring-free kernel boundary.
- [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md) — capability licensing taxonomy.
- [ADR-024](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-024-capability-composition-model.md) — capability composition model.
- [ADR-053](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-053-sku-composition-manifest-format.md) — composition manifest format.
- [ADR-055](https://github.com/exeris-systems/exeris-tooling/blob/main/docs/adr/ADR-055-cap-tier-wall-guard.md) — cap-tier Wall guard.
- [ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md) — signed licence manifest.
- [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md) — capability entitlement enforcement.
- [ADR-099](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-099-compose-identity-as-a-tier-3-platform-sku.md) — the Identity SKU, which lists this cap.

Registry: [`adr-index.md`](https://github.com/exeris-systems/exeris-docs/blob/main/adr-index.md).

## License

Exeris Commercial License 1.1 — see [`LICENSE`](LICENSE). `exeris-caps-credential-store` is a `commercial` capability under [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md): the source is available to read, build, test and evaluate, and production use requires a commercial licence.

The cap enforces that at boot. It registers a kernel `EntitlementRequirement` whose capability id is `exeris-caps-credential-store`, and in a production-class environment the kernel's contract gate refuses to start unless a signed licence manifest lists that id among its entitlements ([ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md), [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md)).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report a suspected vulnerability as described in [`SECURITY.md`](SECURITY.md), never in a public issue.
