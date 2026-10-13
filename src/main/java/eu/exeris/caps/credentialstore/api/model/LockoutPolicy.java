package eu.exeris.caps.credentialstore.api.model;

import eu.exeris.kernel.spi.config.ConfigProvider;

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
 * <p>{@link #fromConfig(ConfigProvider)} reads the three values from kernel configuration under
 * {@value #PREFIX}: {@code max-attempts}, {@code failure-window-seconds} and {@code duration-seconds}. A
 * key that is absent takes its {@link #defaults()} value; a value out of range is refused, never corrected.
 *
 * @param maxAttempts     failures that lock the account; at least 1
 * @param failureWindow   how long failures accumulate before the count starts again; positive
 * @param lockoutDuration how long a locked account stays locked; positive
 */
public record LockoutPolicy(int maxAttempts, Duration failureWindow, Duration lockoutDuration) {

    /** Configuration prefix of the lockout keys. */
    public static final String PREFIX = "caps.credential-store.lockout.";

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

    /**
     * Reads the policy from kernel configuration, falling back to {@link #defaults()} key by key.
     *
     * @param config kernel configuration
     * @return the configured policy
     * @throws IllegalArgumentException if a configured value is out of range
     */
    public static LockoutPolicy fromConfig(ConfigProvider config) {
        Objects.requireNonNull(config, "config must not be null");
        LockoutPolicy d = defaults();
        return new LockoutPolicy(
                config.getIntOrDefault(PREFIX + "max-attempts", d.maxAttempts()),
                seconds(config, PREFIX + "failure-window-seconds", d.failureWindow()),
                seconds(config, PREFIX + "duration-seconds", d.lockoutDuration()));
    }

    static Duration seconds(ConfigProvider config, String key, Duration fallback) {
        return Duration.ofSeconds(config.getLongOrDefault(key, fallback.toSeconds()));
    }

    static void requirePositive(Duration value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}
