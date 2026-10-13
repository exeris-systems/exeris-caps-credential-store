package eu.exeris.caps.credentialstore.api.model;

import java.time.Instant;

/**
 * Current lockout state for a subject.
 *
 * @param failedAttempts consecutive failed login attempts
 * @param lockedUntil timestamp until which the account is locked, or {@code null} if not locked
 */
public record LockoutState(int failedAttempts, Instant lockedUntil) {

    public LockoutState {
        if (failedAttempts < 0) {
            throw new IllegalArgumentException("failedAttempts must be >= 0");
        }
    }

    /**
     * Checks if the account is currently locked with respect to the given timestamp.
     *
     * @param now current timestamp
     * @return {@code true} if locked
     */
    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    public static LockoutState unlocked(int failedAttempts) {
        return new LockoutState(failedAttempts, null);
    }

    public static LockoutState locked(int failedAttempts, Instant lockedUntil) {
        return new LockoutState(failedAttempts, lockedUntil);
    }
}
