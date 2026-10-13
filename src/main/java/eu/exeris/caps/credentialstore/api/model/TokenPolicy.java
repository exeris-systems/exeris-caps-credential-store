package eu.exeris.caps.credentialstore.api.model;

import eu.exeris.kernel.spi.config.ConfigProvider;

import java.time.Duration;
import java.util.Objects;

/**
 * Lifetimes of the single-use tokens this capability issues.
 *
 * <p>{@link #fromConfig(ConfigProvider)} reads the values from kernel configuration under {@value #PREFIX}:
 * {@code verification-validity-seconds}, {@code reset-validity-seconds} and {@code issue-cooldown-seconds}.
 * A key that is absent takes its {@link #defaults()} value; a value out of range is refused.
 *
 * @param verificationValidity how long an account-verification token stays usable; positive
 * @param resetValidity        how long a password-reset token stays usable; positive
 * @param issueCooldown        the minimum interval between two tokens of one kind for one account; a
 *                             request inside it issues nothing; positive
 */
public record TokenPolicy(Duration verificationValidity, Duration resetValidity, Duration issueCooldown) {

    /** Configuration prefix of the token keys. */
    public static final String PREFIX = "caps.credential-store.token.";

    public TokenPolicy {
        LockoutPolicy.requirePositive(verificationValidity, "verificationValidity");
        LockoutPolicy.requirePositive(resetValidity, "resetValidity");
        LockoutPolicy.requirePositive(issueCooldown, "issueCooldown");
    }

    /**
     * Verification tokens last 24 hours, reset tokens 15 minutes, and a new token of either kind is issued at
     * most once a minute per account.
     *
     * @return the default policy
     */
    public static TokenPolicy defaults() {
        return new TokenPolicy(Duration.ofHours(24), Duration.ofMinutes(15), Duration.ofSeconds(60));
    }

    /**
     * Reads the policy from kernel configuration, falling back to {@link #defaults()} key by key.
     *
     * @param config kernel configuration
     * @return the configured policy
     * @throws IllegalArgumentException if a configured value is out of range
     */
    public static TokenPolicy fromConfig(ConfigProvider config) {
        Objects.requireNonNull(config, "config must not be null");
        TokenPolicy d = defaults();
        return new TokenPolicy(
                LockoutPolicy.seconds(config, PREFIX + "verification-validity-seconds", d.verificationValidity()),
                LockoutPolicy.seconds(config, PREFIX + "reset-validity-seconds", d.resetValidity()),
                LockoutPolicy.seconds(config, PREFIX + "issue-cooldown-seconds", d.issueCooldown()));
    }
}
