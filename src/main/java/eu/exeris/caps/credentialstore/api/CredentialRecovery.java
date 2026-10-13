package eu.exeris.caps.credentialstore.api;

import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.exception.TokenCooldownException;

import java.util.UUID;

/**
 * Public service interface for credential recovery (password reset flow).
 *
 * @since 0.1.0
 */
public interface CredentialRecovery {

    /**
     * Requests a password reset token subject to anti-flooding cooldown (60 seconds)
     * and dispatches a notification with the raw token.
     *
     * @param subjectId identity subject identifier
     * @param recipientEmail recipient email address
     * @throws TokenCooldownException if an active reset token was issued less than 60 seconds ago
     * @throws IllegalArgumentException if {@code subjectId} or {@code recipientEmail} is null or blank
     */
    void requestReset(UUID subjectId, String recipientEmail);

    /**
     * Consumes a single-use reset token, updates the subject password, bumps token version,
     * resets lockout, and cascades revocation of all active sessions.
     *
     * @param rawToken raw reset token presented by the user
     * @param newPassword new plaintext password (caller should wipe after invocation)
     * @throws InvalidTokenException if token is missing, expired, or already consumed
     * @throws SamePasswordException if new password is identical to the currently set password
     * @throws IllegalArgumentException if {@code rawToken} is blank or {@code newPassword} is empty
     */
    void consumeReset(String rawToken, char[] newPassword);
}
