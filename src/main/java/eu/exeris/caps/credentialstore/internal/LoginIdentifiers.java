package eu.exeris.caps.credentialstore.internal;

import java.text.Normalizer;
import java.util.Locale;

/**
 * The one normal form of a login identifier: NFC, stripped, lower-cased in {@link Locale#ROOT}. The unique
 * constraint on the stored value is what makes two spellings that differ only in case one login.
 */
public final class LoginIdentifiers {

    /** A 64-character local part, the {@code @} and a 255-character domain (RFC 5321 §4.5.3.1). */
    public static final int MAX_LENGTH = 320;

    private LoginIdentifiers() {
    }

    /**
     * Normalises and validates a login identifier.
     *
     * @param raw identifier as presented
     * @return the normal form
     * @throws IllegalArgumentException if {@code raw} is null or blank, longer than {@link #MAX_LENGTH},
     *                                  contains whitespace, a control character or an invisible format character (zero-width, bidi), or is not one {@code @}
     *                                  between a non-empty local part and a non-empty domain
     */
    public static String normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("loginIdentifier must not be null or blank");
        }
        String normalized = Normalizer.normalize(raw.strip(), Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
        if (normalized.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("loginIdentifier must not exceed " + MAX_LENGTH + " characters");
        }
        if (normalized.codePoints().anyMatch(LoginIdentifiers::isInvisibleOrSpace)) {
            throw new IllegalArgumentException(
                    "loginIdentifier must not contain whitespace, control or invisible format characters");
        }
        int at = normalized.indexOf('@');
        if (at <= 0 || at != normalized.lastIndexOf('@') || at == normalized.length() - 1) {
            throw new IllegalArgumentException("loginIdentifier must be an address of the form local@domain");
        }
        return normalized;
    }

    private static boolean isInvisibleOrSpace(int c) {
        return switch (Character.getType(c)) {
            case Character.FORMAT, Character.SPACE_SEPARATOR, Character.LINE_SEPARATOR,
                 Character.PARAGRAPH_SEPARATOR, Character.CONTROL -> true;
            default -> Character.isWhitespace(c) || Character.isISOControl(c);
        };
    }
}
