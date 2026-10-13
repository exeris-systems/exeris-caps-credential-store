package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.exception.TokenCooldownException;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
import eu.exeris.caps.credentialstore.spi.InMemoryNotificationDispatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DefaultAccountVerification Unit Tests")
class DefaultAccountVerificationTest {

    private InMemoryCredentialRepository repository;
    private InMemoryNotificationDispatcher notificationDispatcher;
    private DefaultAccountVerification verification;

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        notificationDispatcher = new InMemoryNotificationDispatcher();
        verification = new DefaultAccountVerification(
                repository,
                notificationDispatcher,
                null,
                Duration.ofSeconds(60),
                Duration.ofHours(24)
        );
    }

    @Test
    @DisplayName("issue verification generates token, persists hash, and dispatches raw token via notification")
    void issueVerificationGeneratesAndDispatches() {
        UUID subjectId = UUID.randomUUID();
        String email = "operator@exeris.eu";

        // Seed subject credential
        repository.saveCredential(subjectId, "hash", Instant.now());
        assertThat(repository.isEmailVerified(subjectId)).isFalse();

        verification.issueVerification(subjectId, email);

        assertThat(notificationDispatcher.dispatchedNotifications()).hasSize(1);
        InMemoryNotificationDispatcher.DispatchedNotification notification = notificationDispatcher.dispatchedNotifications().get(0);
        assertThat(notification.type()).isEqualTo("VERIFICATION");
        assertThat(notification.subjectId()).isEqualTo(subjectId);
        assertThat(notification.recipientEmail()).isEqualTo(email);
        assertThat(notification.rawToken()).hasSize(32);
    }

    @Test
    @DisplayName("rapid second issue triggers TokenCooldownException")
    void rapidSecondIssueTriggersCooldown() {
        UUID subjectId = UUID.randomUUID();
        String email = "operator@exeris.eu";

        verification.issueVerification(subjectId, email);

        assertThatThrownBy(() -> verification.issueVerification(subjectId, email))
                .isInstanceOf(TokenCooldownException.class)
                .satisfies(ex -> {
                    TokenCooldownException ce = (TokenCooldownException) ex;
                    assertThat(ce.remainingCooldown()).isPositive();
                    assertThat(ce.remainingCooldown()).isLessThanOrEqualTo(Duration.ofSeconds(60));
                });
    }

    @Test
    @DisplayName("consuming valid token marks account verified and returns subjectId")
    void verifyAccountSuccess() {
        UUID subjectId = UUID.randomUUID();
        String email = "operator@exeris.eu";

        repository.saveCredential(subjectId, "hash", Instant.now());
        assertThat(repository.isEmailVerified(subjectId)).isFalse();

        verification.issueVerification(subjectId, email);
        String rawToken = notificationDispatcher.dispatchedNotifications().get(0).rawToken();

        UUID verifiedSubject = verification.verifyAccount(rawToken);
        assertThat(verifiedSubject).isEqualTo(subjectId);
        assertThat(repository.isEmailVerified(subjectId)).isTrue();
    }

    @Test
    @DisplayName("double-spending the same token throws InvalidTokenException")
    void doubleSpendThrowsInvalidToken() {
        UUID subjectId = UUID.randomUUID();
        String email = "operator@exeris.eu";

        repository.saveCredential(subjectId, "hash", Instant.now());
        verification.issueVerification(subjectId, email);
        String rawToken = notificationDispatcher.dispatchedNotifications().get(0).rawToken();

        verification.verifyAccount(rawToken);

        // Second attempt with same raw token
        assertThatThrownBy(() -> verification.verifyAccount(rawToken))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("already been consumed");
    }

    @Test
    @DisplayName("expired token throws InvalidTokenException")
    void expiredTokenThrows() {
        // Create verification service with 1-millisecond validity
        DefaultAccountVerification shortLivedVerification = new DefaultAccountVerification(
                repository,
                notificationDispatcher,
                null,
                Duration.ofMillis(1),
                Duration.ofMillis(1)
        );

        UUID subjectId = UUID.randomUUID();
        shortLivedVerification.issueVerification(subjectId, "test@exeris.eu");
        String rawToken = notificationDispatcher.dispatchedNotifications().get(0).rawToken();

        // Wait to expire
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        assertThatThrownBy(() -> shortLivedVerification.verifyAccount(rawToken))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("expired");
    }

    @Test
    @DisplayName("non-existent token throws InvalidTokenException")
    void nonExistentTokenThrows() {
        assertThatThrownBy(() -> verification.verifyAccount("0123456789abcdef0123456789abcdef"))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("not found");
    }

    @Test
    @DisplayName("parameter validation rejects null and blank inputs")
    void parameterValidations() {
        UUID subjectId = UUID.randomUUID();

        assertThatThrownBy(() -> verification.issueVerification(null, "test@exeris.eu"))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> verification.issueVerification(subjectId, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> verification.issueVerification(subjectId, "   "))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> verification.verifyAccount(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> verification.verifyAccount(""))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
