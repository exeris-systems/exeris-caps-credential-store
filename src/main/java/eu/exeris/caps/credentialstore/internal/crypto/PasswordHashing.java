package eu.exeris.caps.credentialstore.internal.crypto;

import eu.exeris.caps.credentialstore.api.RehashablePasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * The capability's only path to the kernel password encoder: every derivation runs inside the
 * {@link KdfConcurrencyThrottler}, on a copy of the caller's array that is wiped afterwards.
 *
 * <p>{@link #burn(char[])} runs one full verification against a hash of a random password, so a check for
 * an unknown or locked login costs the same derivation as a check for a real one.
 */
public final class PasswordHashing {

    private static final int DUMMY_PASSWORD_LENGTH = 32;

    /** Shared across instances: {@link SecureRandom} is thread-safe and seeding it once is enough. */
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KernelPasswordEncoder encoder;
    private final KdfConcurrencyThrottler throttler;
    private final String dummyHash;

    public PasswordHashing(KernelPasswordEncoder encoder, KdfConcurrencyThrottler throttler) {
        this.encoder = Objects.requireNonNull(encoder, "passwordEncoder must not be null");
        this.throttler = Objects.requireNonNull(throttler, "throttler must not be null");
        char[] dummy = randomPassword();
        try {
            this.dummyHash = encode(dummy);
        } finally {
            Arrays.fill(dummy, '\0');
        }
    }

    public String encode(char[] password) {
        char[] copy = Arrays.copyOf(password, password.length);
        try {
            return throttler.execute(() -> encoder.encode(copy));
        } finally {
            Arrays.fill(copy, '\0');
        }
    }

    public boolean matches(char[] password, String encoded) {
        char[] copy = Arrays.copyOf(password, password.length);
        try {
            return throttler.execute(() -> encoder.matches(copy, encoded));
        } finally {
            Arrays.fill(copy, '\0');
        }
    }

    /** Runs a verification whose result is discarded. */
    public void burn(char[] password) {
        matches(password, dummyHash);
    }

    /** Reports whether the encoder wants {@code encoded} re-encoded, for example after a cost change. */
    public boolean needsRehash(String encoded) {
        return encoder instanceof RehashablePasswordEncoder rehashable && rehashable.needsRehash(encoded);
    }

    private static char[] randomPassword() {
        char[] chars = new char[DUMMY_PASSWORD_LENGTH];
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) ('!' + RANDOM.nextInt('~' - '!' + 1));
        }
        return chars;
    }
}
