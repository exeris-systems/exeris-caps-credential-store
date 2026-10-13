package eu.exeris.caps.credentialstore.api;

import eu.exeris.caps.credentialstore.api.exception.AccountLockedException;
import eu.exeris.caps.credentialstore.api.exception.InvalidCredentialException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.model.CredentialVerificationResult;
import eu.exeris.caps.credentialstore.api.model.LockoutState;

import java.util.UUID;

/**
 * Public service interface for password credential management and verification.
 *
 * <p>All operations are keyed strictly by {@code UUID subjectId} (Layer 5 Domain Primitive).
 *
 * @since 0.1.0
 */
public interface CredentialStore {

    /**
     * Sets or updates the password credential for the given subject.
     *
     * @param subjectId identity subject identifier
     * @param newPassword plaintext new password (caller should wipe after invocation)
     * @throws IllegalArgumentException if {@code subjectId} or {@code newPassword} is null or empty
     */
    void setCredential(UUID subjectId, char[] newPassword);

    /**
     * Verifies a candidate password against the subject's credential, enforcing lockout policies.
     *
     * @param subjectId identity subject identifier
     * @param candidatePassword plaintext candidate password (caller should wipe after invocation)
     * @return outcome of the verification (SUCCESS, INVALID, or LOCKED)
     * @throws IllegalArgumentException if {@code subjectId} or {@code candidatePassword} is null or empty
     */
    CredentialVerificationResult verifyCredential(UUID subjectId, char[] candidatePassword);

    /**
     * Performs a constant-time dummy verification using a valid Argon2id hash.
     * Higher layers (SKU) must invoke this when a subject does not exist to prevent user enumeration
     * via timing attacks.
     *
     * @param candidatePassword candidate password to process
     * @throws IllegalArgumentException if {@code candidatePassword} is null or empty
     */
    void verifyDummy(char[] candidatePassword);

    /**
     * Changes password after verifying the current password.
     * Cascades session revocation and bumps token version.
     *
     * @param subjectId identity subject identifier
     * @param currentPassword current plaintext password
     * @param newPassword new plaintext password
     * @throws InvalidCredentialException if current password does not match
     * @throws SamePasswordException if new password is identical to current password
     */
    void changePassword(UUID subjectId, char[] currentPassword, char[] newPassword);

    /**
     * Resets failed login attempts and clears the lockout status for the given subject.
     *
     * @param subjectId identity subject identifier
     */
    void clearLockout(UUID subjectId);

    /**
     * Returns the current token version for the given subject (used for stateless JWT invalidation).
     *
     * @param subjectId identity subject identifier
     * @return current token version (default 1)
     */
    long getTokenVersion(UUID subjectId);

    /**
     * Returns whether the subject's account/email is verified.
     *
     * @param subjectId identity subject identifier
     * @return {@code true} if verified
     */
    boolean isVerified(UUID subjectId);

    /**
     * Returns the current lockout state for the given subject.
     *
     * @param subjectId identity subject identifier
     * @return lockout state
     */
    LockoutState getLockoutState(UUID subjectId);
}
