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
     * within the cooldown of the {@code TokenPolicy}. A failure of the notification dispatcher is logged and
     * does not reach the caller, so a known account does not answer differently from an unknown one; the
     * token is then undelivered and the user may ask again once the cooldown has passed. The call does the
     * same work in the same order for a known account only up to a point: a known account costs a write and a
     * dispatch, so response time is not constant and must not be treated as a secret.
     *
     * @param loginIdentifier login identifier of the account
     * @throws IllegalArgumentException if {@code loginIdentifier} is null, blank or not an address
     */
    void requestReset(String loginIdentifier);

    /**
     * Consumes a reset token and sets the new password, in one transaction that also increments the token
     * version, clears the lockout, invalidates every other reset token of the subject and marks the login
     * identifier verified, since the token reached it.
     *
     * <p>Every session of the subject is revoked <em>before</em> the password is written, and once more after
     * the commit for a session opened in between. A session store that fails therefore fails the call with
     * the token still usable and the password unchanged; a call that returns has revoked every session that
     * existed when it began. Only the second, post-commit sweep is best effort: its failure is logged and the
     * incremented token version is what refuses the stragglers.
     *
     * @param rawToken    token as delivered
     * @param newPassword new password
     * @throws InvalidTokenException    if the token is unknown, expired, superseded or already consumed; the
     *                                  four are not distinguished, and a failed call leaves the token as it
     *                                  was
     * @throws SamePasswordException    if the new password equals the current one; the token stays usable
     * @throws IllegalArgumentException if {@code rawToken} is blank or {@code newPassword} is empty or outside
     *                                  the {@code PasswordPolicy} window
     */
    void consumeReset(String rawToken, char[] newPassword);
}
