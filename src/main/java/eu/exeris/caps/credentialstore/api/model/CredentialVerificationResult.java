package eu.exeris.caps.credentialstore.api.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Outcome of a credential verification attempt.
 *
 * @param status the verification status (SUCCESS, INVALID, or LOCKED)
 * @param lockedUntil timestamp until which the account is locked (non-null only when status is LOCKED)
 */
public record CredentialVerificationResult(Status status, Instant lockedUntil) {

    public enum Status {
        SUCCESS,
        INVALID,
        LOCKED
    }

    public CredentialVerificationResult {
        Objects.requireNonNull(status, "status must not be null");
        if (status == Status.LOCKED && lockedUntil == null) {
            throw new IllegalArgumentException("lockedUntil must not be null when status is LOCKED");
        }
    }

    public static CredentialVerificationResult success() {
        return new CredentialVerificationResult(Status.SUCCESS, null);
    }

    public static CredentialVerificationResult invalid() {
        return new CredentialVerificationResult(Status.INVALID, null);
    }

    public static CredentialVerificationResult locked(Instant lockedUntil) {
        return new CredentialVerificationResult(Status.LOCKED, Objects.requireNonNull(lockedUntil, "lockedUntil must not be null"));
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
}
