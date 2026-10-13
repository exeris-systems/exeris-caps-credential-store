package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
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

@DisplayName("Password length policy")
class PasswordPolicyEnforcementTest {

    private static final String LOGIN = "user@exeris.eu";
    private static final char[] PASSWORD = "SecretPassword123!".toCharArray();
    private static final PasswordPolicy POLICY = new PasswordPolicy(10, 32);

    private InMemoryCredentialRepository repository;
    private InMemoryNotificationDispatcher dispatcher;
    private CountingPasswordEncoder encoder;
    private MutableClock clock;
    private DefaultCredentialStore store;
    private DefaultCredentialRecovery recovery;
    private UUID subject;

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        dispatcher = new InMemoryNotificationDispatcher();
        encoder = new CountingPasswordEncoder();
        clock = new MutableClock(Instant.parse("2026-10-13T12:00:00Z"));
        PasswordHashing hashing = new PasswordHashing(encoder, new KdfConcurrencyThrottler(2));
        store = new DefaultCredentialStore(repository, hashing, LockoutPolicy.defaults(), POLICY, null, null, clock);
        recovery = new DefaultCredentialRecovery(repository, hashing, dispatcher, null, null,
                new TokenPolicy(Duration.ofHours(1), Duration.ofMinutes(15), Duration.ofSeconds(60)), POLICY, clock);
        subject = UUID.randomUUID();
        store.createCredential(subject, LOGIN, PASSWORD);
    }

    private static char[] of(int length) {
        char[] chars = new char[length];
        java.util.Arrays.fill(chars, 'x');
        return chars;
    }

    @Test
    @DisplayName("a too short or too long password is refused on create before any derivation")
    void createRefusesOutOfWindow() {
        int before = encoder.encodeCount();

        assertThatThrownBy(() -> store.createCredential(UUID.randomUUID(), "a@exeris.eu", of(9)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("at least 10");
        assertThatThrownBy(() -> store.createCredential(UUID.randomUUID(), "b@exeris.eu", of(33)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("at most 32");

        assertThat(encoder.encodeCount()).isEqualTo(before);
        assertThat(repository.findByLoginIdentifier("a@exeris.eu")).isEmpty();
    }

    @Test
    @DisplayName("the window's own bounds are accepted")
    void boundsAreInclusive() {
        store.createCredential(UUID.randomUUID(), "min@exeris.eu", of(10));
        store.createCredential(UUID.randomUUID(), "max@exeris.eu", of(32));
    }

    @Test
    @DisplayName("an oversized password presented for sign-in is refused before any derivation")
    void authenticateRefusesOversized() {
        int matches = encoder.matchCount();

        assertThatThrownBy(() -> store.authenticate(LOGIN, of(33))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.verifyCredential(subject, of(5000))).isInstanceOf(IllegalArgumentException.class);

        assertThat(encoder.matchCount()).isEqualTo(matches);
        assertThat(store.getLockoutState(subject).failedAttempts()).isZero();
    }

    @Test
    @DisplayName("a short presented password is not a policy violation: it is just a wrong password")
    void shortPresentedPasswordIsOrdinaryFailure() {
        assertThat(store.authenticate(LOGIN, of(3)).isInvalid()).isTrue();
    }

    @Test
    @DisplayName("changePassword and consumeReset refuse a new password outside the window and change nothing")
    void changeAndResetRefuseOutOfWindow() {
        String hash = repository.findBySubject(subject).orElseThrow().passwordHash();
        assertThatThrownBy(() -> store.changePassword(subject, PASSWORD, of(9)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.changePassword(subject, PASSWORD, of(33)))
                .isInstanceOf(IllegalArgumentException.class);

        recovery.requestReset(LOGIN);
        String token = dispatcher.dispatchedNotifications().getLast().rawToken();
        assertThatThrownBy(() -> recovery.consumeReset(token, of(9))).isInstanceOf(IllegalArgumentException.class);

        assertThat(repository.findBySubject(subject).orElseThrow().passwordHash()).isEqualTo(hash);
        recovery.consumeReset(token, "ValidNewPassword1".toCharArray());
        assertThat(store.authenticate(LOGIN, "ValidNewPassword1".toCharArray()).isSuccess()).isTrue();
    }

    @Test
    @DisplayName("the policy itself refuses a nonsensical window")
    void policyValidation() {
        assertThatThrownBy(() -> new PasswordPolicy(0, 10)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PasswordPolicy(10, 9)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PasswordPolicy(1, PasswordPolicy.HARD_MAX_LENGTH + 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(PasswordPolicy.defaults()).isEqualTo(new PasswordPolicy(8, 128));
    }
}
