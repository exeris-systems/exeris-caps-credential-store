package eu.exeris.caps.credentialstore.internal.crypto;

import eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Standard JDK-native {@link KernelPasswordEncoder} implementation using PBKDF2 with HMAC-SHA256.
 *
 * <p>Produces and verifies PHC-formatted strings (e.g. {@code $pbkdf2-sha256$i=10000$<salt>$<hash>}).
 * Used as the driver-free default password encoder for standalone capability operation, avoiding any
 * direct compile-time coupling to substrate driver implementations (ADR-099 Obligation 6).
 *
 * @since 0.1.0
 */
public final class Pbkdf2PasswordEncoder implements KernelPasswordEncoder {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String PHC_PREFIX = "$pbkdf2-sha256$i=";
    private static final int DEFAULT_ITERATIONS = 10_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_LENGTH_BITS = 256;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private final int iterations;

    public Pbkdf2PasswordEncoder() {
        this(DEFAULT_ITERATIONS);
    }

    public Pbkdf2PasswordEncoder(int iterations) {
        if (iterations < 1) {
            throw new IllegalArgumentException("iterations must be >= 1");
        }
        this.iterations = iterations;
    }

    @Override
    public String encode(char[] raw) {
        if (raw == null || raw.length == 0) {
            throw new IllegalArgumentException("raw password must not be null or empty");
        }
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(raw, salt, iterations);
        try {
            return PHC_PREFIX + iterations + "$" + HEX.formatHex(salt) + "$" + HEX.formatHex(hash);
        } finally {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(hash, (byte) 0);
        }
    }

    @Override
    public boolean matches(char[] raw, String encoded) {
        if (raw == null || raw.length == 0) {
            throw new IllegalArgumentException("raw password must not be null or empty");
        }
        if (encoded == null || encoded.isEmpty()) {
            throw new IllegalArgumentException("encoded password must not be null or empty");
        }
        if (!encoded.startsWith(PHC_PREFIX)) {
            return false;
        }

        String withoutPrefix = encoded.substring(PHC_PREFIX.length());
        int firstDollar = withoutPrefix.indexOf('$');
        int secondDollar = withoutPrefix.indexOf('$', firstDollar + 1);
        if (firstDollar < 0 || secondDollar < 0) {
            return false;
        }

        int iter;
        try {
            iter = Integer.parseInt(withoutPrefix.substring(0, firstDollar));
        } catch (NumberFormatException e) {
            return false;
        }

        String saltHex = withoutPrefix.substring(firstDollar + 1, secondDollar);
        String expectedHashHex = withoutPrefix.substring(secondDollar + 1);

        byte[] salt;
        byte[] expectedHash;
        try {
            salt = HEX.parseHex(saltHex);
            expectedHash = HEX.parseHex(expectedHashHex);
        } catch (IllegalArgumentException e) {
            return false;
        }

        byte[] derived = derive(raw, salt, iter);
        try {
            return MessageDigest.isEqual(derived, expectedHash);
        } finally {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(expectedHash, (byte) 0);
            Arrays.fill(derived, (byte) 0);
        }
    }

    private byte[] derive(char[] password, byte[] salt, int iter) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iter, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to derive PBKDF2 hash", e);
        } finally {
            spec.clearPassword();
        }
    }
}
