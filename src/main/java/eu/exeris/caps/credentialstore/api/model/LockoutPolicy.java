package eu.exeris.caps.credentialstore.api.model;

import java.time.Duration;
import java.util.Objects;

/**
 * Failed-attempt lockout.
 *
 * <p>Failures are counted within a window that opens at the first failure. Reaching {@code maxAttempts}
 * failures inside the window locks the account for {@code lockoutDuration}. A success clears the count; a
 * failure after the window has closed, or after a lockout has ended, starts a new count at one. Every
 * password check reserves one attempt before the key derivation runs, so concurrent guesses cannot exceed
 * {@code maxAttempts} per window however many arrive at once.
 *
 * @param maxAttempts     failures that lock the account; at least 1
 * @param failureWindow   how long failures accumulate before the count starts again; positive
 * @param lockoutDuration how long a locked account stays locked; positive
 */
public record LockoutPolicy(int maxAttempts, Duration failureWindow, Duration lockoutDuration) {

    public LockoutPolicy {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be >= 1");
        }
        requirePositive(failureWindow, "failureWindow");
        requirePositive(lockoutDuration, "lockoutDuration");
    }

    /**
     * Five failures within fifteen minutes lock the account for fifteen minutes.
     *
     * @return the default policy
     */
    public static LockoutPolicy defaults() {
        return new LockoutPolicy(5, Duration.ofMinutes(15), Duration.ofMinutes(15));
    }

    static void requirePositive(Duration value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}
