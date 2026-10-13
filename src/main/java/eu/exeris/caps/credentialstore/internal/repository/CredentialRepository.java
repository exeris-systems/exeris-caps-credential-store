package eu.exeris.caps.credentialstore.internal.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Internal persistence SPI for credential and token storage.
 */
public interface CredentialRepository {

    void saveCredential(UUID subjectId, String passwordHash, Instant now);

    Optional<CredentialRecord> findCredential(UUID subjectId);

    void updatePassword(UUID subjectId, String newPasswordHash, long newTokenVersion, Instant now);

    void recordFailedLogin(UUID subjectId, int failedAttempts, Instant lockedUntil, Instant now);

    void resetFailedLogins(UUID subjectId, Instant now);

    void unlockAccount(UUID subjectId, Instant now);

    long getTokenVersion(UUID subjectId);

    boolean isEmailVerified(UUID subjectId);

    void setEmailVerified(UUID subjectId, Instant now);

    void saveVerificationToken(UUID id, UUID subjectId, String tokenHash, Instant expiresAt, Instant now);

    Optional<TokenRecord> findLatestVerificationToken(UUID subjectId);

    Optional<TokenRecord> findVerificationTokenByHash(String tokenHash);

    boolean consumeVerificationToken(UUID tokenId, Instant now);

    void saveResetToken(UUID id, UUID subjectId, String tokenHash, Instant expiresAt, Instant now);

    Optional<TokenRecord> findLatestResetToken(UUID subjectId);

    Optional<TokenRecord> findResetTokenByHash(String tokenHash);

    boolean consumeResetToken(UUID tokenId, Instant now);
}
