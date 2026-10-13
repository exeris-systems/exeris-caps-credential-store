package eu.exeris.caps.credentialstore.internal.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("SingleUseHashedToken Unit Tests")
class SingleUseHashedTokenTest {

    @Test
    @DisplayName("generates valid 32-hex raw token and 64-hex SHA-256 hash")
    void generatesValidTokenAndHash() {
        SingleUseHashedToken.GeneratedToken token = SingleUseHashedToken.generate();

        assertThat(token.rawToken())
                .isNotNull()
                .hasSize(32)
                .matches("^[0-9a-f]{32}$");

        assertThat(token.tokenHash())
                .isNotNull()
                .hasSize(64)
                .matches("^[0-9a-f]{64}$");

        // Verify SHA-256 digest reproducibility
        assertThat(SingleUseHashedToken.hashToken(token.rawToken()))
                .isEqualTo(token.tokenHash());
    }

    @Test
    @DisplayName("generated tokens are distinct and non-repeating")
    void generatedTokensAreUnique() {
        Set<String> rawTokens = new HashSet<>();
        Set<String> tokenHashes = new HashSet<>();

        for (int i = 0; i < 100; i++) {
            SingleUseHashedToken.GeneratedToken token = SingleUseHashedToken.generate();
            rawTokens.add(token.rawToken());
            tokenHashes.add(token.tokenHash());
        }

        assertThat(rawTokens).hasSize(100);
        assertThat(tokenHashes).hasSize(100);
    }

    @Test
    @DisplayName("hashToken rejects null or empty input")
    void hashTokenRejectsNullOrEmpty() {
        assertThatThrownBy(() -> SingleUseHashedToken.hashToken(null))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> SingleUseHashedToken.hashToken(""))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> SingleUseHashedToken.hashToken("   "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("hashToken trims whitespace and normalizes case")
    void hashTokenNormalizesWhitespaceAndCase() {
        String raw = "0123456789abcdef0123456789abcdef";
        String withSpacesAndCaps = "  0123456789ABCDEF0123456789ABCDEF  ";

        assertThat(SingleUseHashedToken.hashToken(withSpacesAndCaps))
                .isEqualTo(SingleUseHashedToken.hashToken(raw));
    }
}
