package eu.exeris.caps.credentialstore.api;

import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.exception.TokenCooldownException;

import java.util.UUID;

/**
 * Public service interface for single-use, hashed, expiring account verification tokens.
 *
 * @since 0.1.0
 */
public interface AccountVerification {

    /**
     * Issues a single-use verification token subject to anti-flooding cooldown (60 seconds)
     * and dispatches a notification with the raw token.
     *
     * @param subjectId identity subject identifier
     * @param recipientEmail recipient email address
     * @throws TokenCooldownException if an active verification token was issued less than 60 seconds ago
     * @throws IllegalArgumentException if {@code subjectId} or {@code recipientEmail} is null or blank
     */
    void issueVerification(UUID subjectId, String recipientEmail);

    /**
     * Consumes a single-use verification token, marks the account verified, and returns the subject ID.
     *
     * @param rawToken raw verification token presented by the user
     * @return verified subject identifier
     * @throws InvalidTokenException if token is missing, expired, or already consumed
     * @throws IllegalArgumentException if {@code rawToken} is null or blank
     */
    UUID verifyAccount(String rawToken);
}
