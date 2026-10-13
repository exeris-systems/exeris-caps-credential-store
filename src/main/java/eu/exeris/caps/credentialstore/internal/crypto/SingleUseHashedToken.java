package eu.exeris.caps.credentialstore.internal.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Generates and hashes cryptographically secure single-use tokens for verification and password reset.
 *
 * <p>Generates 16 random bytes (encoded as 32 hex chars), and stores only the SHA-256 hash (64 hex chars).
 *
 * @since 0.1.0
 */
public final class SingleUseHashedToken {

    private static final int RANDOM_BYTE_COUNT = 16;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private SingleUseHashedToken() {
    }

    /**
     * Token pair containing the raw value to be delivered to the user and the SHA-256 hash to persist.
     */
    public record GeneratedToken(String rawToken, String tokenHash) {
        public GeneratedToken {
            Objects.requireNonNull(rawToken, "rawToken must not be null");
            Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        }
    }

    /**
     * Generates a fresh random 16-byte token and computes its SHA-256 hash.
     *
     * @return generated token pair
     */
    public static GeneratedToken generate() {
        byte[] bytes = new byte[RANDOM_BYTE_COUNT];
        SECURE_RANDOM.nextBytes(bytes);
        String raw = HEX.formatHex(bytes);
        String hash = hashToken(raw);
        return new GeneratedToken(raw, hash);
    }

    /**
     * Computes the SHA-256 hash of a raw token string.
     *
     * @param rawToken raw token string
     * @return 64-character lowercase hex digest
     */
    public static String hashToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be null or blank");
        }
        String normalized = rawToken.trim().toLowerCase(java.util.Locale.ROOT);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.getBytes(StandardCharsets.UTF_8));
            return HEX.formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 digest algorithm not available", e);
        }
    }
}
