package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Input hardening")
class InputHardeningTest {

    @Test
    @DisplayName("invisible format characters and non-ASCII spaces cannot make a look-alike login")
    void lookAlikeLoginsAreRefused() {
        for (String login : new String[] {"us​er@exeris.eu", "user@exeris.eu‮", "us er@exeris.eu",
                "user⁠@exeris.eu"}) {
            assertThatThrownBy(() -> LoginIdentifiers.normalize(login)).as(login)
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(LoginIdentifiers.normalize(" User@Exeris.EU ")).isEqualTo("user@exeris.eu");
    }

    @Test
    @DisplayName("a duration that would overflow instant arithmetic is refused")
    void durationsHaveAnUpperBound() {
        Duration huge = Duration.ofSeconds(Long.MAX_VALUE);
        assertThatThrownBy(() -> new LockoutPolicy(5, huge, Duration.ofMinutes(1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TokenPolicy(Duration.ofHours(1), huge, Duration.ofMinutes(1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(new LockoutPolicy(5, Duration.ofDays(3650), Duration.ofDays(3650)).maxAttempts()).isEqualTo(5);
    }
}
