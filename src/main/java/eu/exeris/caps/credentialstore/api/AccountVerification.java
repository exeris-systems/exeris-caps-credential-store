package eu.exeris.caps.credentialstore.api;

import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;

import java.util.UUID;

/**
 * Verification of a credential's login identifier through single-use, expiring tokens that are stored as
 * hashes only.
 *
 * <p>A credential is created unverified, and {@link CredentialStore#authenticate} reports an unverified
 * account as {@code UNVERIFIED} rather than {@code SUCCESS} until a token issued here has been consumed.
 *
 * @since 0.1.0
 */
public interface AccountVerification {

    /**
     * Issues a verification token for an unverified account and sends it to the account's own login
     * identifier, invalidating any token issued before it.
     *
     * <p>Returns normally, without issuing anything, when the login is unknown, already verified, or was
     * sent a token within the cooldown of the {@code TokenPolicy}. The caller therefore answers every
     * request alike, and the answer does not reveal whether an account exists.
     *
     * @param loginIdentifier login identifier of the account
     * @throws IllegalArgumentException if {@code loginIdentifier} is null, blank or not an address
     */
    void issueVerification(String loginIdentifier);

    /**
     * Consumes a verification token and marks its account verified, in one transaction.
     *
     * @param rawToken token as delivered
     * @return the verified subject
     * @throws InvalidTokenException    if the token is unknown, expired, superseded or already consumed; the
     *                                  four are not distinguished
     * @throws IllegalArgumentException if {@code rawToken} is null or blank
     */
    UUID verifyAccount(String rawToken);
}
