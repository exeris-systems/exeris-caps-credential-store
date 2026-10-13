package eu.exeris.caps.credentialstore.internal.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Pbkdf2PasswordEncoder Unit Tests")
class Pbkdf2PasswordEncoderTest {

    private final Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder(1000);

    @Test
    @DisplayName("encode generates valid PHC string and matches verifies raw password")
    void encodeAndMatchesSuccess() {
        char[] password = "SecretMasterPassword123!".toCharArray();
        String phc = encoder.encode(password);

        assertThat(phc)
                .startsWith("$pbkdf2-sha256$i=1000$")
                .hasSizeGreaterThan(40);

        assertThat(encoder.matches(password, phc)).isTrue();
        assertThat(encoder.matches("WrongPassword!".toCharArray(), phc)).isFalse();
    }

    @Test
    @DisplayName("encode produces distinct salts for same password")
    void distinctSaltsPerEncode() {
        char[] password = "Password123!".toCharArray();
        String hash1 = encoder.encode(password);
        String hash2 = encoder.encode(password);

        assertThat(hash1).isNotEqualTo(hash2);
        assertThat(encoder.matches(password, hash1)).isTrue();
        assertThat(encoder.matches(password, hash2)).isTrue();
    }

    @Test
    @DisplayName("matches rejects malformed PHC strings safely")
    void matchesRejectsMalformedPhc() {
        char[] password = "Password123!".toCharArray();
        assertThat(encoder.matches(password, "$invalid$prefix")).isFalse();
        assertThat(encoder.matches(password, "$pbkdf2-sha256$i=invalid$salt$hash")).isFalse();
        assertThat(encoder.matches(password, "$pbkdf2-sha256$i=1000$incomplete")).isFalse();
        assertThat(encoder.matches(password, "$pbkdf2-sha256$i=1000$notHexSalt$notHexHash")).isFalse();
    }

    @Test
    @DisplayName("rejects null or empty inputs")
    void rejectsNullOrEmpty() {
        assertThatThrownBy(() -> encoder.encode(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> encoder.encode(new char[0]))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> encoder.matches(null, "hash"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> encoder.matches("pass".toCharArray(), null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> encoder.matches("pass".toCharArray(), ""))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
