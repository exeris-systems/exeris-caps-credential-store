package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.internal.crypto.SingleUseHashedToken;
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

@DisplayName("DefaultAccountVerification")
class DefaultAccountVerificationTest {

    private static final String LOGIN = "user@exeris.eu";
    private static final char[] PASSWORD = "SecretPassword123!".toCharArray();

    private InMemoryCredentialRepository repository;
    private InMemoryNotificationDispatcher dispatcher;
    private MutableClock clock;
    private TokenPolicy tokens;
    private DefaultCredentialStore store;
    private DefaultAccountVerification verification;
    private UUID subject;

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        dispatcher = new InMemoryNotificationDispatcher();
        clock = new MutableClock(Instant.parse("2026-10-13T12:00:00Z"));
        tokens = new TokenPolicy(Duration.ofHours(24), Duration.ofMinutes(15), Duration.ofSeconds(60));
        store = new DefaultCredentialStore(repository,
                new PasswordHashing(new CountingPasswordEncoder(), new KdfConcurrencyThrottler(2)),
                LockoutPolicy.defaults(), null, null, clock);
        verification = new DefaultAccountVerification(repository, dispatcher, null, tokens, clock);
        subject = UUID.randomUUID();
        store.createCredential(subject, LOGIN, PASSWORD);
    }

    private String issued() {
        return dispatcher.dispatchedNotifications().getLast().rawToken();
    }

    @Test
    @DisplayName("sends a token to the stored login and keeps only its hash")
    void issuesToStoredLogin() {
        verification.issueVerification("User@Exeris.eu");

        assertThat(dispatcher.dispatchedNotifications()).singleElement().satisfies(n -> {
            assertThat(n.type()).isEqualTo("VERIFICATION");
            assertThat(n.subjectId()).isEqualTo(subject);
            assertThat(n.recipientEmail()).isEqualTo(LOGIN);
        });
        assertThat(repository.verificationTokens()).singleElement().satisfies(t -> {
            assertThat(t.tokenHash()).isEqualTo(SingleUseHashedToken.hashToken(issued()));
            assertThat(t.tokenHash()).isNotEqualTo(issued());
            assertThat(t.expiresAt()).isEqualTo(clock.instant().plus(tokens.verificationValidity()));
        });
    }

    @Test
    @DisplayName("issues nothing, and says nothing, for an unknown login, a verified account or inside the cooldown")
    void silentRefusals() {
        verification.issueVerification("nobody@exeris.eu");
        assertThat(dispatcher.dispatchedNotifications()).isEmpty();

        verification.issueVerification(LOGIN);
        verification.issueVerification(LOGIN);
        assertThat(dispatcher.dispatchedNotifications()).hasSize(1);

        verification.verifyAccount(issued());
        clock.advance(tokens.issueCooldown().plusSeconds(1));
        verification.issueVerification(LOGIN);
        assertThat(dispatcher.dispatchedNotifications()).hasSize(1);
    }

    @Test
    @DisplayName("consuming the token verifies the account and unlocks authentication")
    void verifies() {
        assertThat(store.authenticate(LOGIN, PASSWORD).isUnverified()).isTrue();
        verification.issueVerification(LOGIN);

        assertThat(verification.verifyAccount(issued())).isEqualTo(subject);

        assertThat(store.isVerified(subject)).isTrue();
        assertThat(store.authenticate(LOGIN, PASSWORD).isSuccess()).isTrue();
    }

    @Test
    @DisplayName("a token is single-use")
    void singleUse() {
        verification.issueVerification(LOGIN);
        String token = issued();
        verification.verifyAccount(token);

        assertThatThrownBy(() -> verification.verifyAccount(token)).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("an expired token is refused and leaves the account unverified")
    void expired() {
        verification.issueVerification(LOGIN);
        clock.advance(tokens.verificationValidity());

        String token = issued();
        assertThatThrownBy(() -> verification.verifyAccount(token)).isInstanceOf(InvalidTokenException.class);
        assertThat(store.isVerified(subject)).isFalse();
    }

    @Test
    @DisplayName("a newer token supersedes the older one")
    void superseded() {
        verification.issueVerification(LOGIN);
        String first = issued();
        clock.advance(tokens.issueCooldown().plusSeconds(1));
        verification.issueVerification(LOGIN);

        assertThatThrownBy(() -> verification.verifyAccount(first)).isInstanceOf(InvalidTokenException.class);
        assertThat(verification.verifyAccount(issued())).isEqualTo(subject);
    }

    @Test
    @DisplayName("an unknown token is refused with the same message as an expired one")
    void unknownTokenSameMessage() {
        verification.issueVerification(LOGIN);
        String token = issued();
        clock.advance(tokens.verificationValidity());

        String expired = catchMessage(token);
        String unknown = catchMessage("0".repeat(32));
        assertThat(unknown).isEqualTo(expired);
    }

    private String catchMessage(String token) {
        try {
            verification.verifyAccount(token);
            throw new AssertionError("expected InvalidTokenException");
        } catch (InvalidTokenException e) {
            return e.getMessage();
        }
    }

    @Test
    @DisplayName("rejects blank and malformed arguments")
    void rejectsMalformed() {
        assertThatThrownBy(() -> verification.issueVerification(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> verification.issueVerification("not-an-address")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> verification.verifyAccount(" ")).isInstanceOf(IllegalArgumentException.class);
    }
}
