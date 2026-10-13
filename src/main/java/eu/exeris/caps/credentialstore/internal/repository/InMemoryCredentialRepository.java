package eu.exeris.caps.credentialstore.internal.repository;

import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link CredentialRepository} for testing and standalone operation.
 */
public final class InMemoryCredentialRepository implements CredentialRepository {

    private final Map<UUID, CredentialRecord> credentials = new ConcurrentHashMap<>();
    private final Map<UUID, TokenRecord> verificationTokens = new ConcurrentHashMap<>();
    private final Map<UUID, TokenRecord> resetTokens = new ConcurrentHashMap<>();

    @Override
    public void saveCredential(UUID subjectId, String passwordHash, Instant now) {
        credentials.compute(subjectId, (k, existing) -> {
            if (existing == null) {
                return new CredentialRecord(
                        subjectId,
                        passwordHash,
                        false,
                        null,
                        0,
                        null,
                        1L,
                        now,
                        now
                );
            } else {
                return new CredentialRecord(
                        subjectId,
                        passwordHash,
                        existing.emailVerified(),
                        existing.verifiedAt(),
                        existing.failedLoginAttempts(),
                        existing.lockedUntil(),
                        existing.tokenVersion(),
                        existing.createdAt(),
                        now
                );
            }
        });
    }

    @Override
    public Optional<CredentialRecord> findCredential(UUID subjectId) {
        return Optional.ofNullable(credentials.get(subjectId));
    }

    @Override
    public void updatePassword(UUID subjectId, String newPasswordHash, long newTokenVersion, Instant now) {
        credentials.computeIfPresent(subjectId, (k, existing) -> new CredentialRecord(
                subjectId,
                newPasswordHash,
                existing.emailVerified(),
                existing.verifiedAt(),
                0,
                null,
                newTokenVersion,
                existing.createdAt(),
                now
        ));
    }

    @Override
    public void recordFailedLogin(UUID subjectId, int failedAttempts, Instant lockedUntil, Instant now) {
        credentials.computeIfPresent(subjectId, (k, existing) -> new CredentialRecord(
                subjectId,
                existing.passwordHash(),
                existing.emailVerified(),
                existing.verifiedAt(),
                failedAttempts,
                lockedUntil,
                existing.tokenVersion(),
                existing.createdAt(),
                now
        ));
    }

    @Override
    public void resetFailedLogins(UUID subjectId, Instant now) {
        credentials.computeIfPresent(subjectId, (k, existing) -> new CredentialRecord(
                subjectId,
                existing.passwordHash(),
                existing.emailVerified(),
                existing.verifiedAt(),
                0,
                existing.lockedUntil(),
                existing.tokenVersion(),
                existing.createdAt(),
                now
        ));
    }

    @Override
    public void unlockAccount(UUID subjectId, Instant now) {
        credentials.computeIfPresent(subjectId, (k, existing) -> new CredentialRecord(
                subjectId,
                existing.passwordHash(),
                existing.emailVerified(),
                existing.verifiedAt(),
                0,
                null,
                existing.tokenVersion(),
                existing.createdAt(),
                now
        ));
    }

    @Override
    public long getTokenVersion(UUID subjectId) {
        CredentialRecord record = credentials.get(subjectId);
        return record != null ? record.tokenVersion() : 1L;
    }

    @Override
    public boolean isEmailVerified(UUID subjectId) {
        CredentialRecord record = credentials.get(subjectId);
        return record != null && record.emailVerified();
    }

    @Override
    public void setEmailVerified(UUID subjectId, Instant now) {
        credentials.computeIfPresent(subjectId, (k, existing) -> new CredentialRecord(
                subjectId,
                existing.passwordHash(),
                true,
                now,
                existing.failedLoginAttempts(),
                existing.lockedUntil(),
                existing.tokenVersion(),
                existing.createdAt(),
                now
        ));
    }

    @Override
    public void saveVerificationToken(UUID id, UUID subjectId, String tokenHash, Instant expiresAt, Instant now) {
        verificationTokens.put(id, new TokenRecord(id, subjectId, tokenHash, expiresAt, now, null));
    }

    @Override
    public Optional<TokenRecord> findLatestVerificationToken(UUID subjectId) {
        return verificationTokens.values().stream()
                .filter(t -> t.subjectId().equals(subjectId))
                .max(Comparator.comparing(TokenRecord::createdAt));
    }

    @Override
    public Optional<TokenRecord> findVerificationTokenByHash(String tokenHash) {
        return verificationTokens.values().stream()
                .filter(t -> t.tokenHash().equals(tokenHash))
                .findFirst();
    }

    @Override
    public boolean consumeVerificationToken(UUID tokenId, Instant now) {
        final boolean[] consumed = {false};
        verificationTokens.computeIfPresent(tokenId, (k, existing) -> {
            if (existing.consumedAt() == null) {
                consumed[0] = true;
                return new TokenRecord(
                        existing.id(),
                        existing.subjectId(),
                        existing.tokenHash(),
                        existing.expiresAt(),
                        existing.createdAt(),
                        now
                );
            }
            return existing;
        });
        return consumed[0];
    }

    @Override
    public void saveResetToken(UUID id, UUID subjectId, String tokenHash, Instant expiresAt, Instant now) {
        resetTokens.put(id, new TokenRecord(id, subjectId, tokenHash, expiresAt, now, null));
    }

    @Override
    public Optional<TokenRecord> findLatestResetToken(UUID subjectId) {
        return resetTokens.values().stream()
                .filter(t -> t.subjectId().equals(subjectId))
                .max(Comparator.comparing(TokenRecord::createdAt));
    }

    @Override
    public Optional<TokenRecord> findResetTokenByHash(String tokenHash) {
        return resetTokens.values().stream()
                .filter(t -> t.tokenHash().equals(tokenHash))
                .findFirst();
    }

    @Override
    public boolean consumeResetToken(UUID tokenId, Instant now) {
        final boolean[] consumed = {false};
        resetTokens.computeIfPresent(tokenId, (k, existing) -> {
            if (existing.consumedAt() == null) {
                consumed[0] = true;
                return new TokenRecord(
                        existing.id(),
                        existing.subjectId(),
                        existing.tokenHash(),
                        existing.expiresAt(),
                        existing.createdAt(),
                        now
                );
            }
            return existing;
        });
        return consumed[0];
    }
}
