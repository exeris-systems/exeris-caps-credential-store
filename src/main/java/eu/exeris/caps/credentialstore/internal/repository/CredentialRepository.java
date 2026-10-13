package eu.exeris.caps.credentialstore.internal.repository;

import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;

import java.time.Instant;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;

/**
 * Persistence of credentials and their tokens.
 *
 * <p>Every operation that reads a value and writes based on it does so in one statement or one transaction,
 * so concurrent callers cannot interleave between the read and the write. Token hashes are the only form in
 * which a token reaches this interface.
 */
public interface CredentialRepository {

    /**
     * Inserts a new, unverified credential.
     *
     * @return {@code true} if inserted; {@code false} if the subject or the login identifier already has a
     *         credential, in which case nothing was written
     */
    boolean insertCredential(UUID subjectId, String loginIdentifier, String passwordHash, Instant now);

    Optional<CredentialRecord> findBySubject(UUID subjectId);

    Optional<CredentialRecord> findByLoginIdentifier(String loginIdentifier);

    /**
     * Reserves one password check against the lockout budget, atomically.
     *
     * <p>Refused when the account is locked at {@code now}, or when {@code policy.maxAttempts()} attempts are
     * already counted in the current window. Otherwise the count is incremented, or restarted at one when the
     * window has closed or a lockout has ended.
     *
     * @return the row after the reservation, whose password hash the check is to run against; empty if the
     *         reservation was refused or the subject has no credential
     */
    Optional<CredentialRecord> reserveAttempt(UUID subjectId, LockoutPolicy policy, Instant now);

    /**
     * Locks the account if its count has reached the policy's maximum and it is not already locked.
     *
     * @return the end of the lockout this call set; empty if it set none
     */
    Optional<Instant> lockIfExhausted(UUID subjectId, LockoutPolicy policy, Instant now);

    /** Clears the failed-attempt count, the failure window and any lockout. */
    void clearFailures(UUID subjectId, Instant now);

    /**
     * Replaces the hash if it is still {@code expectedHash}, keeping the token version: the password is the
     * same, only its encoding changes.
     *
     * @return {@code true} if replaced
     */
    boolean replacePasswordHash(UUID subjectId, String expectedHash, String newHash, Instant now);

    /**
     * In one transaction: replaces the hash if it is still {@code expectedHash}, increments the token
     * version, clears the lockout and invalidates every outstanding reset token of the subject.
     *
     * @return the new token version; empty if the hash had changed and nothing was written
     */
    OptionalLong changePassword(UUID subjectId, String expectedHash, String newHash, Instant now);

    /**
     * In one transaction, holding the credential row: unless the account is verified, or a verification token
     * was created after {@code cooldownStart}, invalidates the subject's outstanding verification tokens and
     * inserts the new one.
     *
     * @return {@code true} if the token was inserted
     */
    boolean issueVerificationToken(UUID tokenId, UUID subjectId, String tokenHash, Instant expiresAt,
                                   Instant now, Instant cooldownStart);

    /**
     * In one transaction: consumes the token if it is usable at {@code now} and marks its subject verified.
     *
     * @return the verified subject; empty if the token was not usable, in which case nothing was written
     */
    Optional<UUID> consumeVerificationToken(String tokenHash, Instant now);

    /**
     * In one transaction, holding the credential row: unless a reset token was created after
     * {@code cooldownStart}, invalidates the subject's outstanding reset tokens and inserts the new one.
     *
     * @return {@code true} if the token was inserted
     */
    boolean issueResetToken(UUID tokenId, UUID subjectId, String tokenHash, Instant expiresAt,
                            Instant now, Instant cooldownStart);

    Optional<TokenRecord> findResetToken(String tokenHash);

    /**
     * In one transaction: consumes the reset token if it is usable at {@code now}; sets the new hash,
     * increments the token version, clears the lockout and marks the login identifier verified; and
     * invalidates the subject's other reset tokens.
     *
     * @return the new token version; empty if the token was not usable, in which case nothing was written
     */
    OptionalLong consumeResetToken(String tokenHash, String newHash, Instant now);
}
