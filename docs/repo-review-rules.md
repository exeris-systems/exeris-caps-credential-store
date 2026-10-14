---
title: "Review rules for exeris-caps-credential-store"
type: reference
visibility: public
owning-repo: exeris-caps-credential-store
status: active
last-verified: 2026-10-13
---

# Review rules for `exeris-caps-credential-store`

The `repo-routine` extension of `exeris-systems/.github`'s `docs-guardrails-review.md`, applied
**after** its parts and under its severity tags, output format and verdict schema. It adds checks
and raises severities; it lowers nothing and skips nothing. One review, one verdict, one publisher.
A finding cites a rule of this file as `repo-review-rules.md#S<n>`.

**The criteria are not authored here.** They are stated by this repository's `AGENTS.md`,
`README.md`, `CONTRIBUTING.md` and `SECURITY.md`, and by the build that enforces them. This file names the
questions a reviewer must reach for and the severity each answer carries; where a rule restates a
sentence of those documents, the document is the one to read and to change.

## What this repository is answerable for

`exeris-caps-credential-store` is a single-module Exeris capability: Layer 5 domain primitive (identity), licence commercial (Exeris Commercial License 1.1), a proof of concept with
no published artefact. Other capabilities and the SKUs that compose them compile against its
`@Provides` services, so a contract broken here breaks a composition elsewhere while this build stays
green. The shared `code` part judges whether a change is correct. What it cannot know is which of this
capability's surfaces and invariants its own documents promise, and that is what follows.

## Step S — rules of this repository

S1. **The cap-tier Wall holds** (ADR-055, ADR-006; `AGENTS.md` §2). Only what the build's Wall check
    enforces is asserted here: the check is `CapTierWall` in `exeris-tooling`, run by
    `exeris:verify-capabilities` at `process-classes` over the compiled main classes, and it rejects
    a reference to `org.springframework.*`, `io.netty.*`, `reactor.*` or `jakarta.servlet.*`, to
    kernel internals (`eu.exeris.kernel.**.internal.**`), and to a sibling capability's `internal`
    package; only `eu.exeris.kernel.spi.*` is the kernel this capability may name. In a diff: such
    an import in `src/main`; a dependency in `pom.xml` that brings one in; a rename of the package
    root `eu.exeris.caps.credentialstore` or an extra segment in it, because the guard derives the
    capability's name from the segment after `eu.exeris.caps.`;
    `eu.exeris.caps.credentialstore.internal` is private to this capability and
    `eu.exeris.caps.credentialstore.api` is the cross-cap surface, and an `internal` type in a
    public signature → `[HARD BLOCK]`. A Spring, servlet, Netty or reactor import in `src/test` is
    outside what the guard scans and is still forbidden by `AGENTS.md` → `[CONTRACT]`. A
    `kernel-core` or `kernel-community` dependency outside `test` scope → `[HARD BLOCK]`.

S2. **The committed manifest is regenerated, never edited.**
    `src/main/generated/java/cap-manifest.json` is written by `exeris:generate`, and a clean
    `git status` after `mvn verify` shows it matches the declaration. A diff that edits it by hand,
    touches the module class (`@CapabilityModule`, `@Provides`, `@Requires`) without carrying the
    regenerated manifest, carries a manifest change with no declaration change, or leaves a manifest
    that disagrees with the annotations (a `@Provides` version, a `@Requires` range or `optional`
    flag, an `initOrder`) → `[HARD BLOCK]`. A manifest whose `stamp.validated` is not `true` →
    `[HARD BLOCK]`.

S3. **Service contracts are `0.1.0` while the capability is unreleased**
    (`standards/capability-conventions.md` rule 9). While no artefact of this capability has been
    published, every `@Provides` declares `version = "0.1.0"` and every `@Requires` on an unreleased
    contract declares `[0.1.0,0.2.0)`; a declaration at `1.0.0` or higher, or a range that is not
    `[0.1.0,0.2.0)`, → `[CONTRACT]`. A pre-release breaking change does not bump the version: it
    keeps `0.1.0` and its Compatibility impact line is `breaking (ADR-099)` (accepted 2026-10-07),
    or `breaking (ADR-NNN)` of the accepted ADR that governs this capability. **An unreleased
    capability keeps no `accepted-api-changes.json`; the first released version starts it.** The
    reviewer therefore does not ask for that file, an entry in it, or a japicmp baseline on a
    pre-release pull request, and does not read the absence of a version bump as a finding. A pull
    request that publishes the first release is the one in which the register starts, and rule 24 of
    the shared routine then applies in full.

S4. **The entitlement registration stays, and its id is the artifactId.** This is a `commercial`
    capability (Exeris Commercial License 1.1, ADR-023), so
    `META-INF/services/eu.exeris.kernel.spi.contract.EntitlementRequirement` names an implementation
    whose capability id is `exeris-caps-credential-store`, the artifactId and without the groupId
    (ADR-088, ADR-089). The service file deleted, the id changed to anything else, the id no longer
    equal to the artifactId, or the registration made conditional → `[HARD BLOCK]`: in a
    production-class environment the kernel refuses to start without a licence that lists that id.
    The licence in `LICENSE`, the POM and the README moves together, and a change to one alone →
    `[CONTRACT]`.

S5. **No dependency creep.** The runtime classpath stays what the POM declares:
    `exeris-sdk-annotations` at `provided` (every Exeris annotation is `@Retention(SOURCE)`), the
    kernel SPI, and the sibling capabilities the README lists. A new `compile`-scope dependency, a
    logging implementation such as Logback or Log4j (use `System.Logger`, ADR-060), or a new sibling
    capability with no matching `@Requires` or README line → `[CONTRACT]`. Reading an Exeris
    annotation at runtime → `[HARD BLOCK]`.

S6. **The build baseline and the test contract hold** (`AGENTS.md` §2, `CONTRIBUTING.md`).
    `maven.compiler.release` stays 25 and no `--enable-preview` appears in any scope →
    `[HARD BLOCK]`. Tests use JUnit 5 and AssertJ only, with hand-written doubles and no mocking
    framework (ADR-058) → `[CONTRACT]`. A bug fix lands with the test that fails without it →
    `[CONTRACT]` when absent.

S7. **Verification names what ran.** CI runs `mvn verify` on JDK 25 and 26 on every head, so the
    pull request's Verification need not repeat it. A local run may be cited as
    `target/surefire-reports` at `<sha>`, and the reviewer accepts that as the evidence of what ran
    locally. A Verification that claims a pass without a command, report path or sha → `[STYLE]`.

S8. **A password is written only with proof.** `createCredential` inserts a credential for a subject
    and login that have none and throws `CredentialAlreadyExistsException` otherwise;
    `changePassword` needs the current password; `CredentialRecovery.consumeReset` needs a
    single-use reset token. A path that sets or replaces the password hash of an existing credential
    without one of those, including an upsert or an `ON CONFLICT DO UPDATE` in
    `PostgresCredentialRepository` → `[HARD BLOCK]`: it lets a registration or an invitation for an
    address that already has an account take the account.

S9. **The login identifier is the address, and tokens go only to it.** It is stored NFC-normalised,
    stripped, lower-cased and unique. A verification or reset token sent to an address the caller
    supplies, or a second normalisation path → `[HARD BLOCK]`.

S10. **Requests answer alike.** `issueVerification` and `requestReset` return without issuing
    anything for an unknown login, a verified account or a request inside the cooldown, so the
    caller can answer every request the same way. A branch that throws, returns a different value or
    takes a visibly different path for one of those cases → `[HARD BLOCK]`.

S11. **Sign-in is gated on verification, and the outcomes keep their meaning.** `authenticate` and
    `verifyCredential` return `SUCCESS`, `INVALID`, `LOCKED` or `UNVERIFIED`. An unknown login and a
    wrong password are both `INVALID` and both run the key derivation. `UNVERIFIED` is reported only
    after the password matched. A change that returns `UNVERIFIED` before the password check, skips
    the derivation for an unknown login, or lets `SUCCESS` through for an unverified credential →
    `[HARD BLOCK]`.

S12. **Lockout is atomic.** Each password check reserves an attempt with one conditional `UPDATE`
    before the derivation runs, so concurrent guesses cannot exceed the limit. A read-then-write of
    the attempt counter, or a reservation moved after the derivation → `[HARD BLOCK]`.

S13. **Hashing goes through the kernel `KernelPasswordEncoder`.** Its contract requires a
    constant-time comparison, and the SKU supplies the implementation. A concrete encoder or driver
    class named in the capability, a fallback encoder, or a hand-written comparison of a hash or
    token with `equals` or `Arrays.equals` → `[HARD BLOCK]`. Tokens stay stored hashed and
    single-use (`SingleUseHashedToken`).

S14. **Storage is PostgreSQL through the kernel Persistence SPI, with no in-memory production
    store.** The in-memory repository lives in test sources. The tables are deployment-global
    (ADR-099 obligation 10): a `tenant_id` column or a row-level-security policy added to
    `V1__create_credential_store.sql` or to a new migration, with no ADR change → `[CONTRACT]`. A
    migration the module applies by itself → `[CONTRACT]`: the SKU applies
    `CredentialStoreModule.MIGRATIONS`.

## Where this does not apply, and what it costs

The shared `code` and `pr` parts judge correctness, scope, the pull request's body and its commits, and the rules above are not a second copy of them. Whether a change to `internal` is correct is the `code` part's; what this file adds is the list of invariants this capability's own documents state, which a generic review cannot know to look for. Not to the pull request's body and commits, which the shared `pr` part judges, nor to comments
and Javadoc, which the shared `code-docs` part and the Javadoc gate judge.

The cost is that these rules are prose a reviewer applies, not a program. This repository hands the review no `repo-checks` output, so the Wall scan, the manifest comparison and the tests named above are evidence only through the build checks on the pull request, which the reviewer cannot read. A rule the reviewer could only check by running the build is reported as unchecked, not as passing.
