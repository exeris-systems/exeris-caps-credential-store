package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.exception.AccountLockedException;
import eu.exeris.caps.credentialstore.api.exception.CredentialAlreadyExistsException;
import eu.exeris.caps.credentialstore.api.exception.InvalidCredentialException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.model.CredentialVerificationResult;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRecord;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
import eu.exeris.caps.credentialstore.spi.InMemorySessionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DefaultCredentialStore")
class DefaultCredentialStoreTest {

    private static final String LOGIN = "user@exeris.eu";
    private static final char[] PASSWORD = "SecretPassword123!".toCharArray();
    private static final char[] WRONG = "WrongPassword123!".toCharArray();

    private InMemoryCredentialRepository repository;
    private CountingPasswordEncoder encoder;
    private MutableClock clock;
    private InMemorySessionStore sessionStore;
    private LockoutPolicy policy;
    private DefaultCredentialStore store;

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        encoder = new CountingPasswordEncoder();
        clock = new MutableClock(Instant.parse("2026-10-13T12:00:00Z"));
        sessionStore = new InMemorySessionStore();
        policy = new LockoutPolicy(5, Duration.ofMinutes(15), Duration.ofMinutes(15));
        store = new DefaultCredentialStore(repository, new PasswordHashing(encoder, new KdfConcurrencyThrottler(4)),
                policy, PasswordPolicy.defaults(), sessionStore, null, clock);
    }

    private UUID verifiedAccount(String login, char[] password) {
        UUID subject = UUID.randomUUID();
        store.createCredential(subject, login, password);
        markVerified(subject);
        return subject;
    }

    private void markVerified(UUID subject) {
        String hash = "%064x".formatted(subject.getMostSignificantBits() & Long.MAX_VALUE);
        Instant now = clock.instant();
        assertThat(repository.issueVerificationToken(UUID.randomUUID(), subject, hash, now.plusSeconds(60), now,
                now.minusSeconds(60))).isTrue();
        assertThat(repository.consumeVerificationToken(hash, now)).contains(subject);
    }

    @Nested
    @DisplayName("createCredential is insert-only")
    class Create {

        @Test
        @DisplayName("stores an unverified credential under the normalised login")
        void storesUnverified() {
            UUID subject = UUID.randomUUID();

            store.createCredential(subject, "  User@Exeris.EU ", PASSWORD);

            CredentialRecord credential = repository.findBySubject(subject).orElseThrow();
            assertThat(credential.loginIdentifier()).isEqualTo(LOGIN);
            assertThat(credential.emailVerified()).isFalse();
            assertThat(credential.passwordHash()).startsWith("$argon2id$");
            assertThat(store.isVerified(subject)).isFalse();
        }

        @Test
        @DisplayName("refuses a subject that already has a credential and leaves its password unchanged")
        void refusesExistingSubject() {
            UUID subject = verifiedAccount(LOGIN, PASSWORD);
            String before = repository.findBySubject(subject).orElseThrow().passwordHash();

            char[] attackerPassword = "Attacker123!".toCharArray();
            assertThatThrownBy(() -> store.createCredential(subject, "other@exeris.eu", attackerPassword))
                    .isInstanceOf(CredentialAlreadyExistsException.class)
                    .hasMessageNotContaining(subject.toString())
                    .hasMessageNotContaining("other@exeris.eu");

            assertThat(repository.findBySubject(subject).orElseThrow().passwordHash()).isEqualTo(before);
            assertThat(store.authenticate(LOGIN, PASSWORD).isSuccess()).isTrue();
            assertThat(store.authenticate(LOGIN, "Attacker123!".toCharArray()).isInvalid()).isTrue();
        }

        @Test
        @DisplayName("refuses a login that already has a credential, whatever its case, under a new subject")
        void refusesExistingLogin() {
            UUID owner = verifiedAccount(LOGIN, PASSWORD);
            UUID intruder = UUID.randomUUID();

            char[] attackerPassword = "Attacker123!".toCharArray();
            assertThatThrownBy(() -> store.createCredential(intruder, "USER@exeris.eu", attackerPassword))
                    .isInstanceOf(CredentialAlreadyExistsException.class)
                    .hasMessageNotContaining(LOGIN);

            assertThat(repository.findBySubject(intruder)).isEmpty();
            assertThat(store.authenticate(LOGIN, PASSWORD).subjectId()).isEqualTo(owner);
        }

        @Test
        @DisplayName("rejects malformed arguments before anything is written")
        void rejectsMalformedArguments() {
            UUID subject = UUID.randomUUID();
            assertThatThrownBy(() -> store.createCredential(null, LOGIN, PASSWORD)).isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> store.createCredential(subject, " ", PASSWORD)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> store.createCredential(subject, "no-at-sign", PASSWORD)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> store.createCredential(subject, "a@b@c", PASSWORD)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> store.createCredential(subject, "a b@c", PASSWORD)).isInstanceOf(IllegalArgumentException.class);
            String overlong = "x".repeat(320) + "@c";
            assertThatThrownBy(() -> store.createCredential(subject, overlong, PASSWORD)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> store.createCredential(subject, LOGIN, new char[0])).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> store.createCredential(subject, LOGIN, null)).isInstanceOf(IllegalArgumentException.class);
            assertThat(repository.findBySubject(subject)).isEmpty();
        }
    }

    @Nested
    @DisplayName("authenticate")
    class Authenticate {

        @Test
        @DisplayName("a verified account with the right password succeeds and carries its subject")
        void verifiedSucceeds() {
            UUID subject = verifiedAccount(LOGIN, PASSWORD);

            CredentialVerificationResult result = store.authenticate("USER@exeris.eu", PASSWORD);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.subjectId()).isEqualTo(subject);
        }

        @Test
        @DisplayName("an unverified account is UNVERIFIED with the right password and INVALID with a wrong one")
        void unverifiedGate() {
            UUID subject = UUID.randomUUID();
            store.createCredential(subject, LOGIN, PASSWORD);

            CredentialVerificationResult right = store.authenticate(LOGIN, PASSWORD);
            CredentialVerificationResult wrong = store.authenticate(LOGIN, WRONG);

            assertThat(right.isUnverified()).isTrue();
            assertThat(right.subjectId()).isEqualTo(subject);
            assertThat(wrong.isInvalid()).isTrue();
            assertThat(wrong.subjectId()).isNull();
        }

        @Test
        @DisplayName("an unknown login is INVALID, indistinguishable from a wrong password, and runs one derivation")
        void unknownLoginBurnsDerivation() {
            verifiedAccount(LOGIN, PASSWORD);
            int before = encoder.matchCount();

            CredentialVerificationResult unknown = store.authenticate("nobody@exeris.eu", PASSWORD);

            assertThat(unknown).isEqualTo(CredentialVerificationResult.invalid());
            assertThat(store.authenticate(LOGIN, WRONG)).isEqualTo(unknown);
            assertThat(encoder.matchCount() - before).isEqualTo(2);
        }

        @Test
        @DisplayName("maxAttempts failures lock the account; while locked even the right password is LOCKED")
        void lockout() {
            verifiedAccount(LOGIN, PASSWORD);
            for (int i = 1; i < policy.maxAttempts(); i++) {
                assertThat(store.authenticate(LOGIN, WRONG).isInvalid()).isTrue();
            }

            CredentialVerificationResult fifth = store.authenticate(LOGIN, WRONG);
            assertThat(fifth.isLocked()).isTrue();
            assertThat(fifth.lockedUntil()).isEqualTo(clock.instant().plus(policy.lockoutDuration()));

            int before = encoder.matchCount();
            CredentialVerificationResult whileLocked = store.authenticate(LOGIN, PASSWORD);
            assertThat(whileLocked.isLocked()).isTrue();
            assertThat(encoder.matchCount() - before).as("a locked check still costs one derivation").isEqualTo(1);
        }

        @Test
        @DisplayName("after the lockout ends the right password succeeds, and a wrong one counts from one")
        void lockoutExpires() {
            UUID subject = verifiedAccount(LOGIN, PASSWORD);
            for (int i = 0; i < policy.maxAttempts(); i++) {
                store.authenticate(LOGIN, WRONG);
            }
            clock.advance(policy.lockoutDuration());

            assertThat(store.authenticate(LOGIN, WRONG).isInvalid()).isTrue();
            assertThat(store.getLockoutState(subject).failedAttempts()).isEqualTo(1);
            assertThat(store.getLockoutState(subject).isLocked(clock.instant())).isFalse();
            assertThat(store.authenticate(LOGIN, PASSWORD).isSuccess()).isTrue();
        }

        @Test
        @DisplayName("failures older than the window do not count towards a lockout")
        void failureWindow() {
            UUID subject = verifiedAccount(LOGIN, PASSWORD);
            for (int i = 1; i < policy.maxAttempts(); i++) {
                store.authenticate(LOGIN, WRONG);
            }
            clock.advance(policy.failureWindow().plusSeconds(1));

            assertThat(store.authenticate(LOGIN, WRONG).isInvalid()).isTrue();
            assertThat(store.getLockoutState(subject).failedAttempts()).isEqualTo(1);
        }

        @Test
        @DisplayName("a success clears the failure count")
        void successClearsFailures() {
            UUID subject = verifiedAccount(LOGIN, PASSWORD);
            store.authenticate(LOGIN, WRONG);
            store.authenticate(LOGIN, WRONG);

            assertThat(store.authenticate(LOGIN, PASSWORD).isSuccess()).isTrue();
            assertThat(store.getLockoutState(subject).failedAttempts()).isZero();
        }

        @Test
        @DisplayName("concurrent guesses never get more than maxAttempts password checks in a window")
        void concurrentGuessesAreBounded() throws Exception {
            UUID subject = verifiedAccount(LOGIN, PASSWORD);
            int threads = 24;
            CountDownLatch start = new CountDownLatch(1);
            List<Future<CredentialVerificationResult>> results = new ArrayList<>();
            try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
                for (int i = 0; i < threads; i++) {
                    results.add(pool.submit(() -> {
                        start.await();
                        return store.authenticate(LOGIN, WRONG);
                    }));
                }
                start.countDown();
                for (Future<CredentialVerificationResult> result : results) {
                    assertThat(result.get().isSuccess()).isFalse();
                }
            }

            assertThat(store.getLockoutState(subject).failedAttempts()).isEqualTo(policy.maxAttempts());
            assertThat(store.getLockoutState(subject).isLocked(clock.instant())).isTrue();
        }

        @Test
        @DisplayName("a legacy hash is re-encoded on a successful check, keeping the token version")
        void rehashOnSuccess() {
            UUID subject = UUID.randomUUID();
            assertThat(repository.insertCredential(subject, LOGIN, CountingPasswordEncoder.LEGACY_HASH, clock.instant())).isTrue();
            markVerified(subject);

            assertThat(store.authenticate(LOGIN, CountingPasswordEncoder.LEGACY_PASSWORD.toCharArray()).isSuccess()).isTrue();

            CredentialRecord credential = repository.findBySubject(subject).orElseThrow();
            assertThat(credential.passwordHash()).startsWith("$argon2id$");
            assertThat(credential.tokenVersion()).isEqualTo(1L);
            assertThat(store.authenticate(LOGIN, CountingPasswordEncoder.LEGACY_PASSWORD.toCharArray()).isSuccess()).isTrue();
        }

        @Test
        @DisplayName("verifyCredential applies the same gate and lockout to a subject")
        void verifyCredentialBySubject() {
            UUID unverified = UUID.randomUUID();
            store.createCredential(unverified, "new@exeris.eu", PASSWORD);
            UUID verified = verifiedAccount(LOGIN, PASSWORD);

            assertThat(store.verifyCredential(unverified, PASSWORD).isUnverified()).isTrue();
            assertThat(store.verifyCredential(verified, PASSWORD).isSuccess()).isTrue();
            assertThat(store.verifyCredential(UUID.randomUUID(), PASSWORD).isInvalid()).isTrue();
            for (int i = 0; i < policy.maxAttempts(); i++) {
                store.verifyCredential(verified, WRONG);
            }
            assertThat(store.verifyCredential(verified, PASSWORD).isLocked()).isTrue();
        }

        @Test
        @DisplayName("clearLockout unlocks and resets the count")
        void clearLockout() {
            UUID subject = verifiedAccount(LOGIN, PASSWORD);
            for (int i = 0; i < policy.maxAttempts(); i++) {
                store.authenticate(LOGIN, WRONG);
            }

            store.clearLockout(subject);

            assertThat(store.getLockoutState(subject).failedAttempts()).isZero();
            assertThat(store.authenticate(LOGIN, PASSWORD).isSuccess()).isTrue();
        }
    }

    @Nested
    @DisplayName("changePassword")
    class Change {

        @Test
        @DisplayName("needs the current password; bumps the token version, revokes sessions and voids reset tokens")
        void succeeds() {
            UUID subject = verifiedAccount(LOGIN, PASSWORD);
            Instant now = clock.instant();
            repository.issueResetToken(UUID.randomUUID(), subject, "a".repeat(64), now.plusSeconds(900), now, now.minusSeconds(60));
            char[] next = "NextPassword456!".toCharArray();

            store.changePassword(subject, PASSWORD, next);

            assertThat(store.getTokenVersion(subject)).isEqualTo(2L);
            assertThat(sessionStore.revokedSubjects()).containsExactly(subject);
            assertThat(repository.resetTokens()).allSatisfy(t -> assertThat(t.consumedAt()).isNotNull());
            assertThat(store.authenticate(LOGIN, PASSWORD).isInvalid()).isTrue();
            assertThat(store.authenticate(LOGIN, next).isSuccess()).isTrue();
        }

        @Test
        @DisplayName("a wrong current password is refused, counted, and locks at the threshold")
        void wrongCurrentCountsAndLocks() {
            UUID subject = verifiedAccount(LOGIN, PASSWORD);
            char[] next = "NextPassword456!".toCharArray();
            for (int i = 1; i < policy.maxAttempts(); i++) {
                assertThatThrownBy(() -> store.changePassword(subject, WRONG, next))
                        .isInstanceOf(InvalidCredentialException.class);
            }
            assertThatThrownBy(() -> store.changePassword(subject, WRONG, next))
                    .isInstanceOf(AccountLockedException.class);
            assertThatThrownBy(() -> store.changePassword(subject, PASSWORD, next))
                    .isInstanceOf(AccountLockedException.class);
            assertThat(store.getTokenVersion(subject)).isEqualTo(1L);
            assertThat(sessionStore.revokedSubjects()).isEmpty();
        }

        @Test
        @DisplayName("the same password is refused and nothing changes")
        void samePassword() {
            UUID subject = verifiedAccount(LOGIN, PASSWORD);

            char[] samePassword = PASSWORD.clone();
            assertThatThrownBy(() -> store.changePassword(subject, PASSWORD, samePassword))
                    .isInstanceOf(SamePasswordException.class);
            assertThat(store.getTokenVersion(subject)).isEqualTo(1L);
        }

        @Test
        @DisplayName("a subject without a credential is refused as a wrong password")
        void unknownSubject() {
            UUID unknown = UUID.randomUUID();
            assertThatThrownBy(() -> store.changePassword(unknown, PASSWORD, WRONG))
                    .isInstanceOf(InvalidCredentialException.class);
        }

        @Test
        @DisplayName("rejects empty arguments")
        void rejectsEmpty() {
            UUID subject = verifiedAccount(LOGIN, PASSWORD);
            assertThatThrownBy(() -> store.changePassword(null, PASSWORD, WRONG)).isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> store.changePassword(subject, new char[0], WRONG)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> store.changePassword(subject, PASSWORD, null)).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    @DisplayName("reads for a subject without a credential answer the defaults")
    void defaultsForUnknownSubject() {
        UUID subject = UUID.randomUUID();
        assertThat(store.getTokenVersion(subject)).isEqualTo(1L);
        assertThat(store.isVerified(subject)).isFalse();
        assertThat(store.getLockoutState(subject).failedAttempts()).isZero();
    }
}
