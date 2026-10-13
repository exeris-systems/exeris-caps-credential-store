package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
import eu.exeris.caps.credentialstore.spi.NotificationDispatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("A failing notification dispatcher is invisible to the caller of a request path")
class RequestPathsDoNotLeakDeliveryTest {

    private static final String LOGIN = "user@exeris.eu";

    private static final class DownDispatcher implements NotificationDispatcher {
        int calls;

        @Override
        public void sendVerificationToken(UUID subjectId, String recipientEmail, String rawToken) {
            calls++;
            throw new IllegalStateException("provider rejected " + recipientEmail);
        }

        @Override
        public void sendPasswordResetToken(UUID subjectId, String recipientEmail, String rawToken) {
            calls++;
            throw new IllegalStateException("provider rejected " + recipientEmail);
        }
    }

    private DownDispatcher dispatcher;
    private InMemoryCredentialRepository repository;
    private DefaultAccountVerification verification;
    private DefaultCredentialRecovery recovery;

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        dispatcher = new DownDispatcher();
        MutableClock clock = new MutableClock(Instant.parse("2026-10-13T12:00:00Z"));
        PasswordHashing hashing = new PasswordHashing(new CountingPasswordEncoder(), new KdfConcurrencyThrottler(2));
        TokenPolicy tokens = TokenPolicy.defaults();
        new DefaultCredentialStore(repository, hashing, LockoutPolicy.defaults(), PasswordPolicy.defaults(), null, null, clock)
                .createCredential(UUID.randomUUID(), LOGIN, "SecretPassword123!".toCharArray());
        verification = new DefaultAccountVerification(repository, dispatcher, null, tokens, clock);
        recovery = new DefaultCredentialRecovery(repository, hashing, dispatcher, null, null, tokens,
                PasswordPolicy.defaults(), clock);
    }

    @Test
    @DisplayName("requestReset and issueVerification return normally for a known account whose dispatch fails")
    void knownAccountAnswersLikeAnUnknownOne() {
        assertThatCode(() -> recovery.requestReset(LOGIN)).doesNotThrowAnyException();
        assertThatCode(() -> verification.issueVerification(LOGIN)).doesNotThrowAnyException();
        assertThatCode(() -> recovery.requestReset("nobody@exeris.eu")).doesNotThrowAnyException();
        assertThatCode(() -> verification.issueVerification("nobody@exeris.eu")).doesNotThrowAnyException();

        assertThat(dispatcher.calls).as("the known account did attempt delivery").isEqualTo(2);
    }
}
