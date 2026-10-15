package eu.exeris.caps.credentialstore.api.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Outcome of a password check.
 *
 * <p>The statuses are reported in an order that keeps an unauthenticated caller from learning more than the
 * password it supplied proves:
 * <ul>
 *   <li>{@link Status#INVALID} — the login is unknown or the password is wrong. The two are not
 *       distinguished, and both run the key derivation, so the result is the same and the dominant cost
 *       is the same; a known login adds a few cheap writes, so timing is not guaranteed identical.</li>
 *   <li>{@link Status#LOCKED} — the account is locked after repeated failures. Only an existing account can
 *       be locked, so this status confirms that the login exists; a caller that must not confirm it presents
 *       {@code LOCKED} as {@code INVALID}.</li>
 *   <li>{@link Status#UNVERIFIED} — the password is correct but the account's address is not verified.
 *       Reported only after the password matched, so it tells nothing to a caller who does not know the
 *       password.</li>
 *   <li>{@link Status#SUCCESS} — the password is correct and the account is verified.</li>
 * </ul>
 *
 * @param status      the outcome
 * @param subjectId   the authenticated subject; non-null exactly when the status is {@code SUCCESS} or
 *                    {@code UNVERIFIED}
 * @param lockedUntil the end of the lockout; non-null exactly when the status is {@code LOCKED}
 */
public record CredentialVerificationResult(Status status, UUID subjectId, Instant lockedUntil) {

    public enum Status {
        SUCCESS,
        INVALID,
        LOCKED,
        UNVERIFIED
    }

    public CredentialVerificationResult {
        Objects.requireNonNull(status, "status must not be null");
        boolean carriesSubject = status == Status.SUCCESS || status == Status.UNVERIFIED;
        if (carriesSubject != (subjectId != null)) {
            throw new IllegalArgumentException("subjectId must be set exactly for SUCCESS and UNVERIFIED");
        }
        if ((status == Status.LOCKED) != (lockedUntil != null)) {
            throw new IllegalArgumentException("lockedUntil must be set exactly for LOCKED");
        }
    }

    public static CredentialVerificationResult success(UUID subjectId) {
        return new CredentialVerificationResult(Status.SUCCESS, Objects.requireNonNull(subjectId, "subjectId"), null);
    }

    public static CredentialVerificationResult unverified(UUID subjectId) {
        return new CredentialVerificationResult(Status.UNVERIFIED, Objects.requireNonNull(subjectId, "subjectId"), null);
    }

    public static CredentialVerificationResult invalid() {
        return new CredentialVerificationResult(Status.INVALID, null, null);
    }

    public static CredentialVerificationResult locked(Instant lockedUntil) {
        return new CredentialVerificationResult(Status.LOCKED, null, Objects.requireNonNull(lockedUntil, "lockedUntil"));
    }

    public boolean isSuccess() {
        return status == Status.SUCCESS;
    }

    public boolean isInvalid() {
        return status == Status.INVALID;
    }

    public boolean isLocked() {
        return status == Status.LOCKED;
    }

    public boolean isUnverified() {
        return status == Status.UNVERIFIED;
    }
}
