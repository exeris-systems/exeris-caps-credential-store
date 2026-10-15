package eu.exeris.caps.credentialstore.internal.repository;

import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;

/**
 * Test double of {@link CredentialRepository} with the same semantics as the PostgreSQL implementation.
 * Every method holds one monitor, which plays the part of the row lock and the transaction.
 */
public final class InMemoryCredentialRepository implements CredentialRepository {

    private final Map<UUID, CredentialRecord> credentials = new HashMap<>();
    private final List<TokenRecord> verificationTokens = new ArrayList<>();
    private final List<TokenRecord> resetTokens = new ArrayList<>();

    /** Fails the next {@link #consumeResetToken} after the token update, as a rolled-back write would. */
    private boolean failNextResetWrite;

    public synchronized void failNextResetWrite() {
        this.failNextResetWrite = true;
    }

    @Override
    public synchronized boolean insertCredential(UUID subjectId, String loginIdentifier, String passwordHash, Instant now) {
        boolean taken = credentials.containsKey(subjectId)
                || credentials.values().stream().anyMatch(r -> r.loginIdentifier().equals(loginIdentifier));
        if (taken) {
            return false;
        }
        credentials.put(subjectId, new CredentialRecord(subjectId, loginIdentifier, passwordHash, false, null,
                0, null, null, 1L, now, now));
        return true;
    }

    @Override
    public synchronized boolean insertVerifiedCredential(UUID subjectId, String loginIdentifier, String passwordHash, Instant now) {
        boolean taken = credentials.containsKey(subjectId)
                || credentials.values().stream().anyMatch(r -> r.loginIdentifier().equals(loginIdentifier));
        if (taken) {
            return false;
        }
        credentials.put(subjectId, new CredentialRecord(subjectId, loginIdentifier, passwordHash, true, now,
                0, null, null, 1L, now, now));
        return true;
    }

    @Override
    public synchronized Optional<CredentialRecord> findBySubject(UUID subjectId) {
        return Optional.ofNullable(credentials.get(subjectId));
    }

    @Override
    public synchronized Optional<CredentialRecord> findByLoginIdentifier(String loginIdentifier) {
        return credentials.values().stream().filter(r -> r.loginIdentifier().equals(loginIdentifier)).findFirst();
    }

    @Override
    public synchronized Optional<CredentialRecord> reserveAttempt(UUID subjectId, LockoutPolicy policy, Instant now) {
        CredentialRecord r = credentials.get(subjectId);
        if (r == null || (r.lockedUntil() != null && r.lockedUntil().isAfter(now))) {
            return Optional.empty();
        }
        Instant windowStart = now.minus(policy.failureWindow());
        boolean restart = r.failureWindowStartedAt() == null
                || !r.failureWindowStartedAt().isAfter(windowStart)
                || (r.lockedUntil() != null && !r.lockedUntil().isAfter(now));
        if (!restart && r.failedLoginAttempts() >= policy.maxAttempts()) {
            return Optional.empty();
        }
        CredentialRecord updated = restart
                ? copy(r, r.passwordHash(), r.emailVerified(), r.verifiedAt(), 1, now, null, r.tokenVersion(), now)
                : copy(r, r.passwordHash(), r.emailVerified(), r.verifiedAt(), r.failedLoginAttempts() + 1,
                        r.failureWindowStartedAt(), r.lockedUntil(), r.tokenVersion(), now);
        credentials.put(subjectId, updated);
        return Optional.of(updated);
    }

    @Override
    public synchronized Optional<Instant> lockIfExhausted(UUID subjectId, LockoutPolicy policy, Instant now) {
        CredentialRecord r = credentials.get(subjectId);
        if (r == null || r.failedLoginAttempts() < policy.maxAttempts()
                || (r.lockedUntil() != null && r.lockedUntil().isAfter(now))) {
            return Optional.empty();
        }
        Instant lockedUntil = now.plus(policy.lockoutDuration());
        credentials.put(subjectId, copy(r, r.passwordHash(), r.emailVerified(), r.verifiedAt(),
                r.failedLoginAttempts(), r.failureWindowStartedAt(), lockedUntil, r.tokenVersion(), now));
        return Optional.of(lockedUntil);
    }

    @Override
    public synchronized void clearFailures(UUID subjectId, Instant now) {
        CredentialRecord r = credentials.get(subjectId);
        if (r != null) {
            credentials.put(subjectId, copy(r, r.passwordHash(), r.emailVerified(), r.verifiedAt(), 0, null, null,
                    r.tokenVersion(), now));
        }
    }

    @Override
    public synchronized boolean replacePasswordHash(UUID subjectId, String expectedHash, String newHash, Instant now) {
        CredentialRecord r = credentials.get(subjectId);
        if (r == null || !r.passwordHash().equals(expectedHash)) {
            return false;
        }
        credentials.put(subjectId, copy(r, newHash, r.emailVerified(), r.verifiedAt(), r.failedLoginAttempts(),
                r.failureWindowStartedAt(), r.lockedUntil(), r.tokenVersion(), now));
        return true;
    }

    @Override
    public synchronized OptionalLong changePassword(UUID subjectId, String expectedHash, String newHash, Instant now) {
        CredentialRecord r = credentials.get(subjectId);
        if (r == null || !r.passwordHash().equals(expectedHash)) {
            return OptionalLong.empty();
        }
        long version = r.tokenVersion() + 1;
        credentials.put(subjectId, copy(r, newHash, r.emailVerified(), r.verifiedAt(), 0, null, null, version, now));
        supersede(resetTokens, subjectId, now);
        return OptionalLong.of(version);
    }

    @Override
    public synchronized boolean issueVerificationToken(UUID tokenId, UUID subjectId, String tokenHash,
                                                       Instant expiresAt, Instant now, Instant cooldownStart) {
        CredentialRecord r = credentials.get(subjectId);
        if (r == null || r.emailVerified() || recent(verificationTokens, subjectId, cooldownStart)) {
            return false;
        }
        supersede(verificationTokens, subjectId, now);
        verificationTokens.add(new TokenRecord(tokenId, subjectId, tokenHash, expiresAt, now, null));
        return true;
    }

    @Override
    public synchronized Optional<UUID> consumeVerificationToken(String tokenHash, Instant now) {
        Optional<UUID> subject = consume(verificationTokens, tokenHash, now);
        subject.ifPresent(id -> {
            CredentialRecord r = credentials.get(id);
            credentials.put(id, copy(r, r.passwordHash(), true, r.verifiedAt() != null ? r.verifiedAt() : now,
                    r.failedLoginAttempts(), r.failureWindowStartedAt(), r.lockedUntil(), r.tokenVersion(), now));
        });
        return subject;
    }

    @Override
    public synchronized boolean issueResetToken(UUID tokenId, UUID subjectId, String tokenHash,
                                                Instant expiresAt, Instant now, Instant cooldownStart) {
        if (!credentials.containsKey(subjectId) || recent(resetTokens, subjectId, cooldownStart)) {
            return false;
        }
        supersede(resetTokens, subjectId, now);
        resetTokens.add(new TokenRecord(tokenId, subjectId, tokenHash, expiresAt, now, null));
        return true;
    }

    @Override
    public synchronized Optional<TokenRecord> findResetToken(String tokenHash) {
        return resetTokens.stream().filter(t -> t.tokenHash().equals(tokenHash)).findFirst();
    }

    @Override
    public synchronized OptionalLong consumeResetToken(String tokenHash, String newHash, Instant now) {
        List<TokenRecord> resetSnapshot = new ArrayList<>(resetTokens);
        Map<UUID, CredentialRecord> credentialSnapshot = new HashMap<>(credentials);
        Optional<UUID> subject = consume(resetTokens, tokenHash, now);
        if (subject.isEmpty()) {
            return OptionalLong.empty();
        }
        if (failNextResetWrite) {
            failNextResetWrite = false;
            resetTokens.clear();
            resetTokens.addAll(resetSnapshot);
            credentials.clear();
            credentials.putAll(credentialSnapshot);
            throw new IllegalStateException("simulated write failure");
        }
        CredentialRecord r = credentials.get(subject.get());
        long version = r.tokenVersion() + 1;
        credentials.put(r.subjectId(), copy(r, newHash, true, r.verifiedAt() != null ? r.verifiedAt() : now,
                0, null, null, version, now));
        supersede(resetTokens, r.subjectId(), now);
        return OptionalLong.of(version);
    }

    /** Test helper: the verification tokens stored, hashes only. */
    public synchronized List<TokenRecord> verificationTokens() {
        return List.copyOf(verificationTokens);
    }

    /** Test helper: the reset tokens stored, hashes only. */
    public synchronized List<TokenRecord> resetTokens() {
        return List.copyOf(resetTokens);
    }

    private static boolean recent(List<TokenRecord> tokens, UUID subjectId, Instant cooldownStart) {
        return tokens.stream().anyMatch(t -> t.subjectId().equals(subjectId) && t.createdAt().isAfter(cooldownStart));
    }

    private static void supersede(List<TokenRecord> tokens, UUID subjectId, Instant now) {
        tokens.replaceAll(t -> t.subjectId().equals(subjectId) && t.consumedAt() == null
                ? new TokenRecord(t.id(), t.subjectId(), t.tokenHash(), t.expiresAt(), t.createdAt(), now)
                : t);
    }

    private static Optional<UUID> consume(List<TokenRecord> tokens, String tokenHash, Instant now) {
        for (int i = 0; i < tokens.size(); i++) {
            TokenRecord t = tokens.get(i);
            if (t.tokenHash().equals(tokenHash) && t.usableAt(now)) {
                tokens.set(i, new TokenRecord(t.id(), t.subjectId(), t.tokenHash(), t.expiresAt(), t.createdAt(), now));
                return Optional.of(t.subjectId());
            }
        }
        return Optional.empty();
    }

    private static CredentialRecord copy(CredentialRecord r, String hash, boolean verified, Instant verifiedAt,
                                         int failed, Instant windowStart, Instant lockedUntil, long version,
                                         Instant updatedAt) {
        return new CredentialRecord(r.subjectId(), r.loginIdentifier(), hash, verified, verifiedAt, failed,
                windowStart, lockedUntil, version, r.createdAt(), updatedAt);
    }
}
