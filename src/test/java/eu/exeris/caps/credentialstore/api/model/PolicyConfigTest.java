package eu.exeris.caps.credentialstore.api.model;

import eu.exeris.kernel.spi.config.ConfigProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("LockoutPolicy and TokenPolicy from configuration")
class PolicyConfigTest {

    @Test
    @DisplayName("absent keys take the defaults")
    void defaults() {
        ConfigProvider empty = new MapConfig(Map.of());

        assertThat(LockoutPolicy.fromConfig(empty)).isEqualTo(LockoutPolicy.defaults());
        assertThat(TokenPolicy.fromConfig(empty)).isEqualTo(TokenPolicy.defaults());
        assertThat(LockoutPolicy.defaults())
                .isEqualTo(new LockoutPolicy(5, Duration.ofMinutes(15), Duration.ofMinutes(15)));
    }

    @Test
    @DisplayName("configured keys are read under the documented names")
    void configured() {
        ConfigProvider config = new MapConfig(Map.of(
                "caps.credential-store.lockout.max-attempts", "3",
                "caps.credential-store.lockout.failure-window-seconds", "600",
                "caps.credential-store.lockout.duration-seconds", "1800",
                "caps.credential-store.token.verification-validity-seconds", "3600",
                "caps.credential-store.token.reset-validity-seconds", "300",
                "caps.credential-store.token.issue-cooldown-seconds", "30"));

        assertThat(LockoutPolicy.fromConfig(config))
                .isEqualTo(new LockoutPolicy(3, Duration.ofMinutes(10), Duration.ofMinutes(30)));
        assertThat(TokenPolicy.fromConfig(config))
                .isEqualTo(new TokenPolicy(Duration.ofHours(1), Duration.ofMinutes(5), Duration.ofSeconds(30)));
    }

    @Test
    @DisplayName("an out-of-range value is refused, not corrected")
    void refusesOutOfRange() {
        MapConfig noAttempts = new MapConfig(Map.of("caps.credential-store.lockout.max-attempts", "0"));
        MapConfig negativeLockout = new MapConfig(Map.of("caps.credential-store.lockout.duration-seconds", "-1"));
        MapConfig zeroResetValidity = new MapConfig(Map.of("caps.credential-store.token.reset-validity-seconds", "0"));

        assertThatThrownBy(() -> LockoutPolicy.fromConfig(noAttempts)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> LockoutPolicy.fromConfig(negativeLockout)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TokenPolicy.fromConfig(zeroResetValidity)).isInstanceOf(IllegalArgumentException.class);
    }

    /** String-valued configuration, the shape of a properties-backed provider. */
    private record MapConfig(Map<String, String> values) implements ConfigProvider {

        @Override
        public Supplier<KernelSettings> kernelSettings() {
            return KernelSettings::defaults;
        }

        @Override
        public Optional<String> getString(String key) {
            return Optional.ofNullable(values.get(key));
        }

        @Override
        public Optional<Integer> getInt(String key) {
            return getString(key).map(Integer::valueOf);
        }

        @Override
        public Optional<Long> getLong(String key) {
            return getString(key).map(Long::valueOf);
        }

        @Override
        public Optional<Boolean> getBoolean(String key) {
            return getString(key).map(Boolean::valueOf);
        }

        @Override
        public <T> Optional<T> get(String key, Class<T> type) {
            return Optional.empty();
        }

        @Override
        public void watch(String file, String key, Consumer<Object> callback) {
            // static configuration
        }
    }
}
