package eu.exeris.caps.credentialstore.api;

import eu.exeris.caps.credentialstore.api.exception.AccountLockedException;
import eu.exeris.caps.credentialstore.api.exception.CredentialAlreadyExistsException;
import eu.exeris.caps.credentialstore.api.exception.InvalidCredentialException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.model.CredentialVerificationResult;
import eu.exeris.caps.credentialstore.api.model.LockoutState;

import java.util.UUID;

/**
 * Password credentials, one per subject, each bound to a unique login identifier.
 *
 * <p>A password is written in exactly three ways: {@link #createCredential} for a subject and a login that
 * have none, {@link #changePassword} with the current password, and
 * {@link CredentialRecovery#consumeReset} with a single-use reset token. No operation sets the password of
 * an existing credential without one of those proofs.
 *
 * <p>The login identifier is the address that verification and reset tokens are sent to. It is compared
 * after Unicode NFC normalisation, stripping surrounding whitespace and lower-casing in {@code Locale.ROOT},
 * so two spellings that differ only in case are one login.
 *
 * <p>Credentials are per deployment, not per tenant (ADR-099 obligation 10): a subject has one password
 * whatever tenants it is a member of, and tenant scope is applied to membership, not here.
 *
 * <p>Passwords are hashed by the kernel {@code KernelPasswordEncoder} the composition supplies, whose
 * contract requires a constant-time comparison. Every {@code char[]} argument is copied and the copy wiped;
 * the caller wipes its own array.
 *
 * @since 0.1.0
 */
public interface CredentialStore {

    /**
     * Creates the credential of a new account, unverified.
     *
     * @param subjectId       identifier of the new subject
     * @param loginIdentifier login identifier and notification address of the new account
     * @param password        initial password
     * @throws CredentialAlreadyExistsException if the subject or the login identifier already has a
     *                                          credential; nothing is written
     * @throws IllegalArgumentException         if an argument is null, blank or empty, or the login
     *                                          identifier is not an address
     */
    void createCredential(UUID subjectId, String loginIdentifier, char[] password);

    /**
     * Checks a password for a login identifier, applying the lockout policy and the verification gate.
     *
     * <p>See {@link CredentialVerificationResult} for which statuses a caller may show to an unauthenticated
     * client.
     *
     * @param loginIdentifier login identifier presented
     * @param password        candidate password
     * @return the outcome; {@code SUCCESS} carries the subject
     * @throws IllegalArgumentException if an argument is null, blank or empty, or the login identifier is not
     *                                  an address
     */
    CredentialVerificationResult authenticate(String loginIdentifier, char[] password);

    /**
     * Checks a password for a known subject, with the same lockout policy and verification gate as
     * {@link #authenticate}; for re-authentication of a subject that is already signed in.
     *
     * @param subjectId identity subject identifier
     * @param password  candidate password
     * @return the outcome
     * @throws IllegalArgumentException if {@code subjectId} is null or {@code password} is null or empty
     */
    CredentialVerificationResult verifyCredential(UUID subjectId, char[] password);

    /**
     * Replaces the password after checking the current one, increments the token version, clears the lockout,
     * invalidates every outstanding reset token and revokes every session of the subject.
     *
     * <p>Sessions are revoked <em>before</em> the new hash is written, and once more after the commit for a
     * session opened in between. A session store that fails therefore fails the call with the password and
     * the token version unchanged; a call that returns has revoked every session that existed when it began.
     * Only the post-commit sweep is best effort: its failure is logged, and the incremented token version is
     * what refuses the stragglers.
     *
     * <p>A wrong current password counts as a failed attempt under the lockout policy.
     *
     * @param subjectId       identity subject identifier
     * @param currentPassword current password
     * @param newPassword     new password
     * @throws InvalidCredentialException if the subject has no credential or the current password does not
     *                                    match
     * @throws AccountLockedException     if the account is locked, or this failure locked it
     * @throws SamePasswordException      if the new password equals the current one
     */
    void changePassword(UUID subjectId, char[] currentPassword, char[] newPassword);

    /**
     * Clears the failed-attempt count and any lockout; an administrative operation.
     *
     * @param subjectId identity subject identifier
     */
    void clearLockout(UUID subjectId);

    /**
     * Returns the subject's token version, which a password change or reset increments so that tokens
     * carrying an older version can be refused.
     *
     * @param subjectId identity subject identifier
     * @return the current token version, {@code 1} for a subject without a credential
     */
    long getTokenVersion(UUID subjectId);

    /**
     * Returns whether the subject's login identifier is verified.
     *
     * @param subjectId identity subject identifier
     * @return {@code true} if verified; {@code false} also for a subject without a credential
     */
    boolean isVerified(UUID subjectId);

    /**
     * Returns the subject's failed-attempt count and lockout.
     *
     * @param subjectId identity subject identifier
     * @return the lockout state; unlocked with no failures for a subject without a credential
     */
    LockoutState getLockoutState(UUID subjectId);
}
