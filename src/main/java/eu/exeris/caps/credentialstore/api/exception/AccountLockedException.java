package eu.exeris.caps.credentialstore.api.exception;

import java.time.Instant;
import java.util.Objects;

/**
 * Thrown when an account is locked due to excessive failed login attempts.
 */
public class AccountLockedException extends CredentialException {

    private final Instant lockedUntil;

    public AccountLockedException(String message, Instant lockedUntil) {
        super(message);
        this.lockedUntil = Objects.requireNonNull(lockedUntil, "lockedUntil must not be null");
    }

    public Instant lockedUntil() {
        return lockedUntil;
    }
}
