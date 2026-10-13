package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.internal.crypto.SingleUseHashedToken;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
import eu.exeris.caps.credentialstore.spi.InMemoryNotificationDispatcher;
import eu.exeris.caps.credentialstore.spi.InMemorySessionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DefaultCredentialRecovery")
class DefaultCredentialRecoveryTest {

    private static final String LOGIN = "user@exeris.eu";
    private static final char[] PASSWORD = "SecretPassword123!".toCharArray();
    private static final char[] NEXT = "NextPassword456!".toCharArray();

    private InMemoryCredentialRepository repository;
    private InMemoryNotificationDispatcher dispatcher;
    private InMemorySessionStore sessions;
    private MutableClock clock;
    private TokenPolicy tokens;
    private LockoutPolicy lockout;
    private DefaultCredentialStore store;
    private DefaultCredentialRecovery recovery;
    private UUID subject;

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        dispatcher = new InMemoryNotificationDispatcher();
        sessions = new InMemorySessionStore();
        clock = new MutableClock(Instant.parse("2026-10-13T12:00:00Z"));
        tokens = new TokenPolicy(Duration.ofHours(24), Duration.ofMinutes(15), Duration.ofSeconds(60));
        lockout = LockoutPolicy.defaults();
        PasswordHashing hashing = new PasswordHashing(new CountingPasswordEncoder(), new KdfConcurrencyThrottler(2));
        store = new DefaultCredentialStore(repository, hashing, lockout, sessions, null, clock);
        recovery = new DefaultCredentialRecovery(repository, hashing, dispatcher, sessions, null, tokens, clock);
        subject = UUID.randomUUID();
        store.createCredential(subject, LOGIN, PASSWORD);
    }

    private String issued() {
        return dispatcher.dispatchedNotifications().getLast().rawToken();
    }

    @Test
    @DisplayName("sends a reset token to the stored login and keeps only its hash")
    void issuesToStoredLogin() {
        recovery.requestReset("USER@exeris.eu");

        assertThat(dispatcher.dispatchedNotifications()).singleElement().satisfies(n -> {
            assertThat(n.type()).isEqualTo("PASSWORD_RESET");
            assertThat(n.recipientEmail()).isEqualTo(LOGIN);
        });
        assertThat(repository.resetTokens()).singleElement()
                .satisfies(t -> assertThat(t.tokenHash()).isEqualTo(SingleUseHashedToken.hashToken(issued())));
    }

    @Test
    @DisplayName("issues nothing, and says nothing, for an unknown login or inside the cooldown")
    void silentRefusals() {
        recovery.requestReset("nobody@exeris.eu");
        assertThat(dispatcher.dispatchedNotifications()).isEmpty();

        recovery.requestReset(LOGIN);
        recovery.requestReset(LOGIN);
        assertThat(dispatcher.dispatchedNotifications()).hasSize(1);
    }

    @Test
    @DisplayName("consuming a token sets the password, bumps the version, clears lockout, verifies and revokes sessions")
    void consumes() {
        for (int i = 0; i < lockout.maxAttempts(); i++) {
            store.authenticate(LOGIN, "Wrong123!".toCharArray());
        }
        recovery.requestReset(LOGIN);

        recovery.consumeReset(issued(), NEXT);

        assertThat(store.getTokenVersion(subject)).isEqualTo(2L);
        assertThat(store.getLockoutState(subject).failedAttempts()).isZero();
        assertThat(store.isVerified(subject)).as("the token reached the address").isTrue();
        assertThat(sessions.revokedSubjects()).containsExactly(subject);
        assertThat(store.authenticate(LOGIN, PASSWORD).isInvalid()).isTrue();
        assertThat(store.authenticate(LOGIN, NEXT).isSuccess()).isTrue();
    }

    @Test
    @DisplayName("a token is single-use")
    void singleUse() {
        recovery.requestReset(LOGIN);
        String token = issued();
        recovery.consumeReset(token, NEXT);

        assertThatThrownBy(() -> recovery.consumeReset(token, "Another789!".toCharArray()))
                .isInstanceOf(InvalidTokenException.class);
        assertThat(store.getTokenVersion(subject)).isEqualTo(2L);
    }

    @Test
    @DisplayName("an expired token is refused and the password is unchanged")
    void expired() {
        recovery.requestReset(LOGIN);
        clock.advance(tokens.resetValidity());

        assertThatThrownBy(() -> recovery.consumeReset(issued(), NEXT)).isInstanceOf(InvalidTokenException.class);
        assertThat(store.getTokenVersion(subject)).isEqualTo(1L);
    }

    @Test
    @DisplayName("a newer reset token supersedes the older one")
    void superseded() {
        recovery.requestReset(LOGIN);
        String first = issued();
        clock.advance(tokens.issueCooldown().plusSeconds(1));
        recovery.requestReset(LOGIN);

        assertThatThrownBy(() -> recovery.consumeReset(first, NEXT)).isInstanceOf(InvalidTokenException.class);
        recovery.consumeReset(issued(), NEXT);
        assertThat(store.getTokenVersion(subject)).isEqualTo(2L);
    }

    @Test
    @DisplayName("a password change voids an outstanding reset token")
    void changeVoidsResetToken() {
        String verifyHash = "b".repeat(64);
        Instant now = clock.instant();
        repository.issueVerificationToken(UUID.randomUUID(), subject, verifyHash, now.plusSeconds(60), now, now.minusSeconds(60));
        repository.consumeVerificationToken(verifyHash, now);
        recovery.requestReset(LOGIN);

        store.changePassword(subject, PASSWORD, NEXT);

        assertThatThrownBy(() -> recovery.consumeReset(issued(), "Another789!".toCharArray()))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("the same password is refused and the token stays usable")
    void samePasswordKeepsToken() {
        recovery.requestReset(LOGIN);
        String token = issued();

        assertThatThrownBy(() -> recovery.consumeReset(token, PASSWORD.clone())).isInstanceOf(SamePasswordException.class);
        recovery.consumeReset(token, NEXT);
        assertThat(store.getTokenVersion(subject)).isEqualTo(2L);
    }

    @Test
    @DisplayName("a failed write leaves both the token and the password as they were")
    void failedWriteRollsBack() {
        recovery.requestReset(LOGIN);
        String token = issued();
        repository.failNextResetWrite();

        assertThatThrownBy(() -> recovery.consumeReset(token, NEXT)).isInstanceOf(IllegalStateException.class);
        assertThat(repository.resetTokens()).singleElement().satisfies(t -> assertThat(t.consumedAt()).isNull());
        assertThat(store.getTokenVersion(subject)).isEqualTo(1L);
        assertThat(sessions.revokedSubjects()).isEmpty();

        recovery.consumeReset(token, NEXT);
        assertThat(store.getTokenVersion(subject)).isEqualTo(2L);
    }

    @Test
    @DisplayName("rejects blank and malformed arguments")
    void rejectsMalformed() {
        assertThatThrownBy(() -> recovery.requestReset(" ")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> recovery.consumeReset(null, NEXT)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> recovery.consumeReset("token", new char[0])).isInstanceOf(IllegalArgumentException.class);
    }
}
