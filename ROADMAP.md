---
title: "Credential store capability — Roadmap"
type: roadmap
visibility: public
owning-repo: exeris-caps-credential-store
status: active
last-verified: 2026-10-15
---

# `exeris-caps-credential-store` — Roadmap

This repository is a proof of concept. It provides `CredentialStore`, `AccountVerification` and
`CredentialRecovery`, and [`README.md`](README.md) describes what they do. This file records what the
proof of concept does not cover, read together with the code, and the pull request that closes a gap
updates it.

Milestones are versions, not dates. A "Before 0.1.0" item blocks the first release and has a tracking
issue in the `0.1.0` milestone; a "Later" item has none until it is scheduled.

---

## Before 0.1.0

### A verified address carries the password of whoever created the credential

`createCredential` needs no proof that the caller controls the login identifier, and `verifyAccount`
only marks the credential verified. A credential created for another person's address, with a password the
creator chose, therefore authenticates with that password as soon as the address owner follows the
verification link. The README claims that a password is written only with proof and that sign-in is gated
on verification; both hold, and the combination still leaves an account whose verified address and whose
password belong to different people. The Identity SKU cannot close this from outside, because it cannot
tell who verifies. The code is in `internal/DefaultAccountVerification.java` (`verifyAccount`) and
`internal/repository/PostgresCredentialRepository.java` (`CONSUME_VERIFICATION_TOKEN`, `MARK_VERIFIED`);
the rule for what verification does to the earlier password is open. Tracked in
[#12](https://github.com/exeris-systems/exeris-caps-credential-store/issues/12).

---

## Later

### Credentials whose password is longer than the maximum

`PasswordPolicy.maxLength` (default 128 UTF-16 code units) is checked for every password the capability
is handed, including one presented for verification, so a stored credential whose password exceeds the
maximum can neither `authenticate` nor `changePassword`: both throw `IllegalArgumentException` before any
key derivation. The way back is the reset flow: `CredentialRecovery.requestReset` and `consumeReset` need
no current password and accept any password inside the policy window
(`internal/DefaultCredentialRecovery.java`). Nothing in the capability lists the affected subjects or
starts that flow for them, and there is no operation that imports an existing password hash (the only
entry point, `createCredential`, takes a plaintext password), so a migration from another store writes
rows by SQL and must plan the resets itself, and its login endpoint must answer the exception like an
`INVALID` result. This waits on the migration path the Identity SKU needs.

### Kernel-supplied requirements are declared optional

All five `@Requires` edges are `optional = true`, among them `TransactionalExecutor` and
`KernelPasswordEncoder`, although the wiring constructor refuses to build without either
(`CredentialStoreModule.java`). The capability graph resolves edges between capability modules only, so a
kernel SPI type cannot be a mandatory edge and the manifest understates what the capability needs to
start. This waits on [exeris-tooling#409](https://github.com/exeris-systems/exeris-tooling/issues/409),
which would let the resolver treat a kernel SPI type as satisfied by the kernel. The kernel's 0.13.0
development branch publishes `KernelProviders.TRANSACTIONAL_EXECUTOR`
(`exeris-kernel-spi/.../context/KernelProviders.java`); `initialize()` here does nothing, and taking the
executor from it, instead of through the constructor, is not done. No `KernelPasswordEncoder` entry exists
there, so the SKU keeps supplying the encoder.

### Migrations are applied by the composing SKU

`CredentialStoreModule.MIGRATIONS` lists the schema file, and nothing in the capability applies it. The
kernel's Community migration runner applies a fixed list (`MIGRATION_RESOURCES` in
`CommunityPersistenceEngine`), and its ledger keys applied migrations by version alone
(`SchemaHistoryLedger`), so two capabilities that each ship a `V1` file cannot share it. Until the kernel
accepts migrations from capabilities, a deployment that skips the SKU's step has no tables and the first
call fails. This waits on the kernel.

### `NotificationDispatcher` and `SessionStore` are local copies

Delivery and session revocation go through interfaces declared in `spi/`, not through the sibling
capabilities. `exeris-caps-session-management` now declares its own `SessionStore` in its `api` package,
with a different signature (`int revokeAllForSubject(UUID)`, against `void` here), so the two cannot be
wired to each other without an adapter. No repository for a notification-dispatch capability exists in the
organisation. The ADR-099 table also lists `service-boundary-core` among this capability's requirements,
and no code here refers to it. Aligning these needs the sibling contracts to settle and an ADR-099 or
capability amendment.

### A composition without a `SessionStore` revokes nothing

The wiring constructor accepts `null` for the `SessionStore`, and `changePassword` and `consumeReset` then
complete without revoking any session (`internal/SessionRevocation.java`). ADR-099 obligation 9 says a
completed reset or change revokes every session of the subject, and the capability cannot tell whether a
composition meant to omit the store. Whether a production composition may do so, or the constructor should
refuse it, is a design question for the Identity SKU.

### Session revocation around a password write is not one commit

The session store has its own unit of work, so revocation runs before the write and once more after the
commit. A session opened with the old password between the two is refused only by the incremented token
version if the second sweep fails; that failure is logged, not thrown
(`internal/SessionRevocation.java`). Closing the window needs a session store that can join the credential
transaction, or one that checks the token version on every use.

### A correct password clears concurrent failures

`DefaultCredentialStore.check` clears the failure count and any lock with an unconditional update after a
successful comparison (`CLEAR_FAILURES` in `PostgresCredentialRepository.java`). A guess that locked the
account a moment earlier is cleared by a concurrent correct sign-in. Only a caller who knows the password
can trigger it, so it gives a guesser nothing, and the count after a mixed burst is not exact. A
conditional clear keyed on the reservation would make it exact.

### Key-derivation queue is unbounded

`KdfConcurrencyThrottler.execute` waits for a permit without a bound, and the module builds it with the
default of `max(4, 2 * availableProcessors)` permits and no configuration. A burst of unauthenticated
sign-in requests queues as many waiting threads, each holding a copy of its password, as the caller lets
in. The caller bounds the queue today (a connection limit or a rate limit in front of the endpoint); a
timeout or a configurable limit belongs here.

### Delivery is synchronous and not durable

`requestReset` and `issueVerification` commit the token and then call the `NotificationDispatcher` in the
request path. A failed delivery is logged, and the token is lost until a new request is allowed; there is no
outbox and no retry (`internal/DefaultCredentialRecovery.java`, `internal/DefaultAccountVerification.java`).
The response time of a known account also differs from an unknown one, because only the known one writes
and dispatches. An outbox, or an asynchronous dispatcher supplied by the SKU, would remove both.

### Failed sign-ins for an unknown login are not audited

`authenticate` records `AUTH_FAILURE` only for an existing account; a failure for a login with no
credential returns `INVALID` without an event (`internal/DefaultCredentialStore.java`). A spray across
many addresses therefore leaves no trace in the audit trail from this capability. Whether to record it, and
what to record without storing attacker-chosen text, needs a rule.

### Used and expired tokens are never removed

Verification and reset tokens are marked consumed, never deleted, and the migration defines no retention
(`db/migration/exeris-caps-credential-store/V1__create_credential_store.sql`). The two token tables grow
with every request. A purge needs the scheduling SPI or a SKU job, and a retention period.

### Password rules beyond length

`PasswordPolicy` imposes a length window and nothing else. Passwords are compared as UTF-16 code units
without Unicode normalisation, so the same password typed on two platforms can differ, and no check
refuses a common or breached password. Both need a rule before they are code.

### No credential removal or login change

`CredentialStore` has no operation that deletes a credential or moves it to another login identifier. The
token tables cascade on delete, but a SKU can only remove a row by SQL, and an address change has no
re-verification step. This waits on the Identity SKU's account lifecycle flows.
