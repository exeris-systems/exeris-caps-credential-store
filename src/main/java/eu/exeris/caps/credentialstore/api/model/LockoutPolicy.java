package eu.exeris.caps.credentialstore.api.model;

import java.time.Duration;
import java.util.Objects;

/**
 * Account lockout policy configuration parameters.
 *
 * @param maxAttempts maximum consecutive failed login attempts permitted before the account is locked
 * @param lockoutDuration duration for which the account remains locked
 */
public record LockoutPolicy(int maxAttempts, Duration lockoutDuration) {

    public LockoutPolicy {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be >= 1");
        }
        Objects.requireNonNull(lockoutDuration, "lockoutDuration must not be null");
        if (lockoutDuration.isNegative() || lockoutDuration.isZero()) {
            throw new IllegalArgumentException("lockoutDuration must be positive");
        }
    }

    /**
     * Default lockout policy: 5 failed attempts, 15 minutes lockout duration.
     *
     * @return default lockout policy
     */
    public static LockoutPolicy defaults() {
        return new LockoutPolicy(5, Duration.ofMinutes(15));
    }
}
