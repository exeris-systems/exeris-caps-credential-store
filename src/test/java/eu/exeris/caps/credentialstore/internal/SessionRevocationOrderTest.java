package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.exception.InvalidCredentialException;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
import eu.exeris.caps.credentialstore.spi.InMemoryNotificationDispatcher;
import eu.exeris.caps.credentialstore.spi.SessionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Session revocation cannot be skipped by a password write")
class SessionRevocationOrderTest {

    private static final String LOGIN = "user@exeris.eu";
    private static final char[] PASSWORD = "SecretPassword123!".toCharArray();
    private static final char[] NEXT = "NextPassword456!".toCharArray();

    /** Fails on the calls whose 1-based number is below {@code failUntil}, and records every attempt. */
    private static final class FlakySessionStore implements SessionStore {
        final List<UUID> attempts = new ArrayList<>();
        int failUntil;

        @Override
        public void revokeAllForSubject(UUID subjectId) {
            attempts.add(subjectId);
            if (attempts.size() < failUntil) {
                throw new IllegalStateException("session store down");
            }
        }
    }

    private InMemoryCredentialRepository repository;
    private InMemoryNotificationDispatcher dispatcher;
    private FlakySessionStore sessions;
    private DefaultCredentialStore store;
    private DefaultCredentialRecovery recovery;
    private UUID subject;

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        dispatcher = new InMemoryNotificationDispatcher();
        sessions = new FlakySessionStore();
        MutableClock clock = new MutableClock(Instant.parse("2026-10-13T12:00:00Z"));
        PasswordHashing hashing = new PasswordHashing(new CountingPasswordEncoder(), new KdfConcurrencyThrottler(2));
        store = new DefaultCredentialStore(repository, hashing, LockoutPolicy.defaults(), PasswordPolicy.defaults(),
                sessions, null, clock);
        recovery = new DefaultCredentialRecovery(repository, hashing, dispatcher, sessions, null,
                TokenPolicy.defaults(), PasswordPolicy.defaults(), clock);
        subject = UUID.randomUUID();
        store.createCredential(subject, LOGIN, PASSWORD);
    }

    @Test
    @DisplayName("changePassword: a failing session store leaves the password and token version as they were")
    void changePasswordFailsClosed() {
        sessions.failUntil = 2;
        String hash = repository.findBySubject(subject).orElseThrow().passwordHash();

        assertThatThrownBy(() -> store.changePassword(subject, PASSWORD, NEXT))
                .isInstanceOf(IllegalStateException.class);

        assertThat(repository.findBySubject(subject).orElseThrow().passwordHash()).isEqualTo(hash);
        assertThat(store.getTokenVersion(subject)).isEqualTo(1L);
        assertThat(sessions.attempts).hasSize(1);

        store.changePassword(subject, PASSWORD, NEXT);
        assertThat(store.getTokenVersion(subject)).isEqualTo(2L);
        assertThat(sessions.attempts).as("revoked before the write and again after it").hasSize(3);
    }

    @Test
    @DisplayName("consumeReset: a failing session store leaves the token usable and the password unchanged")
    void consumeResetFailsClosed() {
        recovery.requestReset(LOGIN);
        String token = dispatcher.dispatchedNotifications().getLast().rawToken();
        sessions.failUntil = 2;
        String hash = repository.findBySubject(subject).orElseThrow().passwordHash();

        assertThatThrownBy(() -> recovery.consumeReset(token, NEXT)).isInstanceOf(IllegalStateException.class);

        assertThat(repository.findBySubject(subject).orElseThrow().passwordHash()).isEqualTo(hash);
        assertThat(store.getTokenVersion(subject)).isEqualTo(1L);
        assertThat(repository.resetTokens()).singleElement().satisfies(t -> assertThat(t.consumedAt()).isNull());

        recovery.consumeReset(token, NEXT);
        assertThat(store.getTokenVersion(subject)).isEqualTo(2L);
    }

    @Test
    @DisplayName("a session store that fails only after the commit does not turn the success into a failure")
    void postCommitSweepFailureIsLogged() {
        // The pre-write revocation (call 1) succeeds; every later call fails.
        FlakyAfterFirst afterFirst = new FlakyAfterFirst();
        PasswordHashing hashing = new PasswordHashing(new CountingPasswordEncoder(), new KdfConcurrencyThrottler(2));
        MutableClock clock = new MutableClock(Instant.parse("2026-10-13T12:00:00Z"));
        DefaultCredentialStore lenient = new DefaultCredentialStore(repository, hashing, LockoutPolicy.defaults(),
                PasswordPolicy.defaults(), afterFirst, null, clock);

        lenient.changePassword(subject, PASSWORD, NEXT);

        assertThat(afterFirst.calls).isEqualTo(2);
        assertThat(store.getTokenVersion(subject)).isEqualTo(2L);
    }

    @Test
    @DisplayName("a wrong current password never reaches the session store")
    void wrongPasswordRevokesNothing() {
        assertThatThrownBy(() -> store.changePassword(subject, "WrongPassword999".toCharArray(), NEXT))
                .isInstanceOf(InvalidCredentialException.class);

        assertThat(sessions.attempts).isEmpty();
    }

    private static final class FlakyAfterFirst implements SessionStore {
        int calls;

        @Override
        public void revokeAllForSubject(UUID subjectId) {
            if (++calls > 1) {
                throw new IllegalStateException("session store down");
            }
        }
    }
}
