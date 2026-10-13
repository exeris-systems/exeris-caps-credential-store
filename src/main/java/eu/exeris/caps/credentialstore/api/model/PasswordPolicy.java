package eu.exeris.caps.credentialstore.api.model;

import eu.exeris.kernel.spi.config.ConfigProvider;

import java.util.Objects;

/**
 * Length window for a password, enforced before any key derivation runs.
 *
 * <p>The minimum applies to a password being set (create, change, reset); the maximum applies to every
 * password the capability is given, including one presented for verification, because a key derivation over
 * a multi-megabyte input is a denial-of-service lever. Length is counted in UTF-16 code units, the unit of a
 * {@code char[]}. No composition rule is imposed.
 *
 * <p>{@link #fromConfig(ConfigProvider)} reads {@code min-length} and {@code max-length} under
 * {@value #PREFIX}; an absent key takes its {@link #defaults()} value and a value out of range is refused,
 * never corrected.
 *
 * @param minLength shortest password that may be set; at least 1
 * @param maxLength longest password accepted anywhere; at least {@code minLength} and at most
 *                  {@value #HARD_MAX_LENGTH}
 * @since 0.1.0
 */
public record PasswordPolicy(int minLength, int maxLength) {

    /** Configuration prefix of the password keys. */
    public static final String PREFIX = "caps.credential-store.password.";

    /** Upper bound for {@link #maxLength()}, whatever the configuration says. */
    public static final int HARD_MAX_LENGTH = 4096;

    public PasswordPolicy {
        if (minLength < 1) {
            throw new IllegalArgumentException("minLength must be >= 1");
        }
        if (maxLength < minLength) {
            throw new IllegalArgumentException("maxLength must be >= minLength");
        }
        if (maxLength > HARD_MAX_LENGTH) {
            throw new IllegalArgumentException("maxLength must be <= " + HARD_MAX_LENGTH);
        }
    }

    /**
     * At least 8 and at most 128 code units.
     *
     * @return the default policy
     */
    public static PasswordPolicy defaults() {
        return new PasswordPolicy(8, 128);
    }

    /**
     * Reads the policy from kernel configuration.
     *
     * @param config the configuration source; required
     * @return the configured policy
     * @throws IllegalArgumentException if a configured value is out of range
     */
    public static PasswordPolicy fromConfig(ConfigProvider config) {
        Objects.requireNonNull(config, "config must not be null");
        PasswordPolicy d = defaults();
        return new PasswordPolicy(
                config.getIntOrDefault(PREFIX + "min-length", d.minLength()),
                config.getIntOrDefault(PREFIX + "max-length", d.maxLength()));
    }
}
