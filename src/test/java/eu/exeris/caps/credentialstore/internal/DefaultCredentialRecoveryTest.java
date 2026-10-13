package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.exception.TokenCooldownException;
import eu.exeris.caps.credentialstore.api.model.CredentialVerificationResult;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
import eu.exeris.caps.credentialstore.spi.InMemoryNotificationDispatcher;
import eu.exeris.caps.credentialstore.spi.InMemorySessionStore;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DefaultCredentialRecovery Unit Tests")
class DefaultCredentialRecoveryTest {

    private InMemoryCredentialRepository repository;
    private Argon2idPasswordEncoder passwordEncoder;
    private KdfConcurrencyThrottler throttler;
    private InMemoryNotificationDispatcher notificationDispatcher;
    private InMemorySessionStore sessionStore;
    private DefaultCredentialRecovery recovery;

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        passwordEncoder = new Argon2idPasswordEncoder(new PasswordEncoderConfig(8192, 1, 1, 16));
        throttler = new KdfConcurrencyThrottler(4);
        notificationDispatcher = new InMemoryNotificationDispatcher();
        sessionStore = new InMemorySessionStore();
        recovery = new DefaultCredentialRecovery(
                repository,
                passwordEncoder,
                throttler,
                notificationDispatcher,
                sessionStore,
                null,
                Duration.ofSeconds(60),
                Duration.ofMinutes(15)
        );
    }

    @Test
    @DisplayName("requestReset generates token and sends notification")
    void requestResetSuccess() {
        UUID subjectId = UUID.randomUUID();
        String email = "operator@exeris.eu";

        recovery.requestReset(subjectId, email);

        assertThat(notificationDispatcher.dispatchedNotifications()).hasSize(1);
        InMemoryNotificationDispatcher.DispatchedNotification notification = notificationDispatcher.dispatchedNotifications().get(0);
        assertThat(notification.type()).isEqualTo("PASSWORD_RESET");
        assertThat(notification.subjectId()).isEqualTo(subjectId);
        assertThat(notification.recipientEmail()).isEqualTo(email);
        assertThat(notification.rawToken()).hasSize(32);
    }

    @Test
    @DisplayName("rapid second requestReset triggers TokenCooldownException")
    void rapidSecondResetTriggersCooldown() {
        UUID subjectId = UUID.randomUUID();
        String email = "operator@exeris.eu";

        recovery.requestReset(subjectId, email);

        assertThatThrownBy(() -> recovery.requestReset(subjectId, email))
                .isInstanceOf(TokenCooldownException.class)
                .satisfies(ex -> {
                    TokenCooldownException ce = (TokenCooldownException) ex;
                    assertThat(ce.remainingCooldown()).isPositive();
                    assertThat(ce.remainingCooldown()).isLessThanOrEqualTo(Duration.ofSeconds(60));
                });
    }

    @Test
    @DisplayName("consumeReset updates password, clears lockout, bumps token_version, and revokes sessions")
    void consumeResetSuccess() {
        UUID subjectId = UUID.randomUUID();
        String oldHash = passwordEncoder.encode("OldPassword123!".toCharArray());
        repository.saveCredential(subjectId, oldHash, Instant.now());
        repository.recordFailedLogin(subjectId, 5, Instant.now().plusSeconds(600), Instant.now());

        assertThat(repository.getTokenVersion(subjectId)).isEqualTo(1L);

        recovery.requestReset(subjectId, "user@exeris.eu");
        String rawToken = notificationDispatcher.dispatchedNotifications().get(0).rawToken();

        recovery.consumeReset(rawToken, "BrandNewPassword789!".toCharArray());

        // Token version bumped
        assertThat(repository.getTokenVersion(subjectId)).isEqualTo(2L);

        // Lockout cleared
        assertThat(repository.findCredential(subjectId).orElseThrow().lockedUntil()).isNull();
        assertThat(repository.findCredential(subjectId).orElseThrow().failedLoginAttempts()).isZero();

        // Active sessions revoked
        assertThat(sessionStore.revokedSubjects()).containsExactly(subjectId);

        // Old password invalid, new password matches
        assertThat(passwordEncoder.matches("OldPassword123!".toCharArray(), repository.findCredential(subjectId).orElseThrow().passwordHash())).isFalse();
        assertThat(passwordEncoder.matches("BrandNewPassword789!".toCharArray(), repository.findCredential(subjectId).orElseThrow().passwordHash())).isTrue();
    }

    @Test
    @DisplayName("consumeReset with identical password throws SamePasswordException")
    void consumeResetSamePasswordThrows() {
        UUID subjectId = UUID.randomUUID();
        String currentHash = passwordEncoder.encode("IdenticalPassword123!".toCharArray());
        repository.saveCredential(subjectId, currentHash, Instant.now());

        recovery.requestReset(subjectId, "user@exeris.eu");
        String rawToken = notificationDispatcher.dispatchedNotifications().get(0).rawToken();

        assertThatThrownBy(() -> recovery.consumeReset(rawToken, "IdenticalPassword123!".toCharArray()))
                .isInstanceOf(SamePasswordException.class)
                .hasMessageContaining("cannot be identical");

        // Sessions should not have been revoked
        assertThat(sessionStore.revokedSubjects()).isEmpty();
    }

    @Test
    @DisplayName("double-spending reset token throws InvalidTokenException")
    void doubleSpendingResetTokenThrows() {
        UUID subjectId = UUID.randomUUID();
        String currentHash = passwordEncoder.encode("Password123!".toCharArray());
        repository.saveCredential(subjectId, currentHash, Instant.now());

        recovery.requestReset(subjectId, "user@exeris.eu");
        String rawToken = notificationDispatcher.dispatchedNotifications().get(0).rawToken();

        recovery.consumeReset(rawToken, "NewPass1!".toCharArray());

        assertThatThrownBy(() -> recovery.consumeReset(rawToken, "NewPass2!".toCharArray()))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("already been consumed");
    }

    @Test
    @DisplayName("expired reset token throws InvalidTokenException")
    void expiredResetTokenThrows() {
        DefaultCredentialRecovery shortLived = new DefaultCredentialRecovery(
                repository,
                passwordEncoder,
                throttler,
                notificationDispatcher,
                sessionStore,
                null,
                Duration.ofMillis(1),
                Duration.ofMillis(1)
        );

        UUID subjectId = UUID.randomUUID();
        String currentHash = passwordEncoder.encode("Password123!".toCharArray());
        repository.saveCredential(subjectId, currentHash, Instant.now());

        shortLived.requestReset(subjectId, "user@exeris.eu");
        String rawToken = notificationDispatcher.dispatchedNotifications().get(0).rawToken();

        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        assertThatThrownBy(() -> shortLived.consumeReset(rawToken, "NewPass!".toCharArray()))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("expired");
    }

    @Test
    @DisplayName("parameter validation rejects invalid inputs")
    void parameterValidations() {
        UUID subjectId = UUID.randomUUID();

        assertThatThrownBy(() -> recovery.requestReset(null, "user@exeris.eu"))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> recovery.requestReset(subjectId, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> recovery.requestReset(subjectId, "   "))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> recovery.consumeReset(null, "pass".toCharArray()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> recovery.consumeReset("", "pass".toCharArray()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> recovery.consumeReset("token", null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> recovery.consumeReset("token", new char[0]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("consumeReset does not consume token if password encoding fails")
    void tokenNotConsumedIfEncodingFails() {
        // Create an encoder that fails on encode
        eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder failingEncoder =
                new eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder() {
                    @Override
                    public String encode(char[] raw) {
                        throw new RuntimeException("Simulated KDF failure");
                    }

                    @Override
                    public boolean matches(char[] raw, String encoded) {
                        return false;
                    }
                };

        DefaultCredentialRecovery recoveryWithFailingEncoder = new DefaultCredentialRecovery(
                repository,
                failingEncoder,
                throttler,
                notificationDispatcher,
                sessionStore,
                null,
                Duration.ofSeconds(60),
                Duration.ofMinutes(15)
        );

        UUID subjectId = UUID.randomUUID();
        String existingHash = passwordEncoder.encode("ExistingPassword123!".toCharArray());
        repository.saveCredential(subjectId, existingHash, Instant.now());

        recovery.requestReset(subjectId, "user@exeris.eu");
        String rawToken = notificationDispatcher.dispatchedNotifications().get(0).rawToken();

        // Attempt consumeReset - should fail on encode
        assertThatThrownBy(() -> recoveryWithFailingEncoder.consumeReset(rawToken, "NewPassword123!".toCharArray()))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Simulated KDF failure");

        // Token must still NOT be consumed!
        String tokenHash = eu.exeris.caps.credentialstore.internal.crypto.SingleUseHashedToken.hashToken(rawToken);
        assertThat(repository.findResetTokenByHash(tokenHash).orElseThrow().consumedAt()).isNull();

        // Normal recovery can still consume the token
        recovery.consumeReset(rawToken, "NewPassword123!".toCharArray());
        assertThat(repository.findResetTokenByHash(tokenHash).orElseThrow().consumedAt()).isNotNull();
    }
}
