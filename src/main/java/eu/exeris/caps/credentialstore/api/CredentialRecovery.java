package eu.exeris.caps.credentialstore.api;

import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;

/**
 * Password reset through single-use, expiring tokens that are stored as hashes only.
 *
 * @since 0.1.0
 */
public interface CredentialRecovery {

    /**
     * Issues a reset token and sends it to the account's own login identifier, invalidating any reset token
     * issued before it.
     *
     * <p>Returns normally, without issuing anything, when the login is unknown or was sent a reset token
     * within the cooldown of the {@code TokenPolicy}, so the caller answers every request alike.
     *
     * @param loginIdentifier login identifier of the account
     * @throws IllegalArgumentException if {@code loginIdentifier} is null, blank or not an address
     */
    void requestReset(String loginIdentifier);

    /**
     * Consumes a reset token and sets the new password, in one transaction that also increments the token
     * version, clears the lockout, invalidates every other reset token of the subject and marks the login
     * identifier verified, since the token reached it. Every session of the subject is then revoked.
     *
     * @param rawToken    token as delivered
     * @param newPassword new password
     * @throws InvalidTokenException    if the token is unknown, expired, superseded or already consumed; the
     *                                  four are not distinguished, and a failed call leaves the token as it
     *                                  was
     * @throws SamePasswordException    if the new password equals the current one; the token stays usable
     * @throws IllegalArgumentException if {@code rawToken} is blank or {@code newPassword} is empty
     */
    void consumeReset(String rawToken, char[] newPassword);
}
