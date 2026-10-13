package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.exception.AccountLockedException;
import eu.exeris.caps.credentialstore.api.exception.InvalidCredentialException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.model.CredentialVerificationResult;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.LockoutState;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
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

@DisplayName("DefaultCredentialStore Unit Tests")
class DefaultCredentialStoreTest {

    private InMemoryCredentialRepository repository;
    private Argon2idPasswordEncoder passwordEncoder;
    private KdfConcurrencyThrottler throttler;
    private LockoutPolicy lockoutPolicy;
    private InMemorySessionStore sessionStore;
    private DefaultCredentialStore credentialStore;

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        // Use minimal Argon2id cost parameters to make test suite blazingly fast
        passwordEncoder = new Argon2idPasswordEncoder(new PasswordEncoderConfig(8192, 1, 1, 16));
        throttler = new KdfConcurrencyThrottler(4);
        lockoutPolicy = new LockoutPolicy(5, Duration.ofMinutes(15));
        sessionStore = new InMemorySessionStore();
        credentialStore = new DefaultCredentialStore(
                repository,
                passwordEncoder,
                throttler,
                lockoutPolicy,
                sessionStore,
                null
        );
    }

    @Test
    @DisplayName("set credential and verify successfully with matching password")
    void setAndVerifySuccess() {
        UUID subjectId = UUID.randomUUID();
        char[] password = "SecretPassword123!".toCharArray();

        credentialStore.setCredential(subjectId, password);

        CredentialVerificationResult result = credentialStore.verifyCredential(subjectId, password);
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.status()).isEqualTo(CredentialVerificationResult.Status.SUCCESS);
        assertThat(result.lockedUntil()).isNull();
    }

    @Test
    @DisplayName("verify non-existent subject returns INVALID")
    void verifyNonExistentSubjectReturnsInvalid() {
        UUID unknown = UUID.randomUUID();
        CredentialVerificationResult result = credentialStore.verifyCredential(unknown, "password".toCharArray());
        assertThat(result.isInvalid()).isTrue();
    }

    @Test
    @DisplayName("failed password verification increments count and returns INVALID")
    void failedVerificationIncrementsCount() {
        UUID subjectId = UUID.randomUUID();
        credentialStore.setCredential(subjectId, "correctPassword".toCharArray());

        CredentialVerificationResult result = credentialStore.verifyCredential(subjectId, "wrongPassword".toCharArray());
        assertThat(result.isInvalid()).isTrue();

        LockoutState state = credentialStore.getLockoutState(subjectId);
        assertThat(state.failedAttempts()).isEqualTo(1);
        assertThat(state.isLocked(Instant.now())).isFalse();
    }

    @Test
    @DisplayName("5 consecutive failed logins trigger account lockout")
    void consecutiveFailedLoginsTriggerLockout() {
        UUID subjectId = UUID.randomUUID();
        credentialStore.setCredential(subjectId, "correctPassword".toCharArray());

        for (int i = 1; i <= 4; i++) {
            CredentialVerificationResult result = credentialStore.verifyCredential(subjectId, "wrong".toCharArray());
            assertThat(result.isInvalid()).isTrue();
            assertThat(credentialStore.getLockoutState(subjectId).failedAttempts()).isEqualTo(i);
        }

        // 5th failed attempt -> LOCKED
        CredentialVerificationResult lockResult = credentialStore.verifyCredential(subjectId, "wrong".toCharArray());
        assertThat(lockResult.isLocked()).isTrue();
        assertThat(lockResult.status()).isEqualTo(CredentialVerificationResult.Status.LOCKED);
        assertThat(lockResult.lockedUntil()).isAfter(Instant.now());

        LockoutState lockedState = credentialStore.getLockoutState(subjectId);
        assertThat(lockedState.failedAttempts()).isEqualTo(5);
        assertThat(lockedState.isLocked(Instant.now())).isTrue();

        // While locked, even correct password returns LOCKED
        CredentialVerificationResult whileLockedResult = credentialStore.verifyCredential(subjectId, "correctPassword".toCharArray());
        assertThat(whileLockedResult.isLocked()).isTrue();
    }

    @Test
    @DisplayName("clearLockout resets failed attempts and unlocks account")
    void clearLockoutUnlocksAccount() {
        UUID subjectId = UUID.randomUUID();
        credentialStore.setCredential(subjectId, "correctPassword".toCharArray());

        for (int i = 1; i <= 5; i++) {
            credentialStore.verifyCredential(subjectId, "wrong".toCharArray());
        }
        assertThat(credentialStore.getLockoutState(subjectId).isLocked(Instant.now())).isTrue();

        credentialStore.clearLockout(subjectId);

        LockoutState state = credentialStore.getLockoutState(subjectId);
        assertThat(state.failedAttempts()).isZero();
        assertThat(state.isLocked(Instant.now())).isFalse();

        // Verification with correct password now succeeds
        CredentialVerificationResult result = credentialStore.verifyCredential(subjectId, "correctPassword".toCharArray());
        assertThat(result.isSuccess()).isTrue();
    }

    @Test
    @DisplayName("successful verification resets failed attempts counter")
    void successfulVerificationResetsFailedCounter() {
        UUID subjectId = UUID.randomUUID();
        credentialStore.setCredential(subjectId, "correctPassword".toCharArray());

        credentialStore.verifyCredential(subjectId, "wrong".toCharArray());
        credentialStore.verifyCredential(subjectId, "wrong".toCharArray());
        assertThat(credentialStore.getLockoutState(subjectId).failedAttempts()).isEqualTo(2);

        CredentialVerificationResult result = credentialStore.verifyCredential(subjectId, "correctPassword".toCharArray());
        assertThat(result.isSuccess()).isTrue();
        assertThat(credentialStore.getLockoutState(subjectId).failedAttempts()).isZero();
    }

    @Test
    @DisplayName("verifyDummy runs without error on dummy hash")
    void verifyDummyRunsSuccessfully() {
        credentialStore.verifyDummy("anyCandidatePassword".toCharArray());
    }

    @Test
    @DisplayName("changePassword succeeds with correct current password and bumps token version and revokes sessions")
    void changePasswordSuccess() {
        UUID subjectId = UUID.randomUUID();
        credentialStore.setCredential(subjectId, "OldPassword123!".toCharArray());
        assertThat(credentialStore.getTokenVersion(subjectId)).isEqualTo(1L);

        credentialStore.changePassword(subjectId, "OldPassword123!".toCharArray(), "NewPassword456!".toCharArray());

        // Token version bumped
        assertThat(credentialStore.getTokenVersion(subjectId)).isEqualTo(2L);

        // SessionStore received revocation call
        assertThat(sessionStore.revokedSubjects()).containsExactly(subjectId);

        // Old password no longer matches
        CredentialVerificationResult oldResult = credentialStore.verifyCredential(subjectId, "OldPassword123!".toCharArray());
        assertThat(oldResult.isInvalid()).isTrue();

        // New password matches
        CredentialVerificationResult newResult = credentialStore.verifyCredential(subjectId, "NewPassword456!".toCharArray());
        assertThat(newResult.isSuccess()).isTrue();
    }

    @Test
    @DisplayName("changePassword throws InvalidCredentialException on wrong current password")
    void changePasswordWrongCurrentThrows() {
        UUID subjectId = UUID.randomUUID();
        credentialStore.setCredential(subjectId, "OldPassword123!".toCharArray());

        assertThatThrownBy(() -> credentialStore.changePassword(
                subjectId,
                "WrongCurrentPassword!".toCharArray(),
                "NewPassword456!".toCharArray()
        )).isInstanceOf(InvalidCredentialException.class)
          .hasMessageContaining("Current password does not match");

        // Sessions must not have been revoked
        assertThat(sessionStore.revokedSubjects()).isEmpty();
    }

    @Test
    @DisplayName("changePassword throws SamePasswordException when new password equals current password")
    void changePasswordSamePasswordThrows() {
        UUID subjectId = UUID.randomUUID();
        credentialStore.setCredential(subjectId, "SamePassword123!".toCharArray());

        assertThatThrownBy(() -> credentialStore.changePassword(
                subjectId,
                "SamePassword123!".toCharArray(),
                "SamePassword123!".toCharArray()
        )).isInstanceOf(SamePasswordException.class)
          .hasMessageContaining("New password cannot be identical");
    }

    @Test
    @DisplayName("argument validations on null and empty parameters")
    void argumentValidations() {
        UUID subjectId = UUID.randomUUID();

        assertThatThrownBy(() -> credentialStore.setCredential(null, "pass".toCharArray()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> credentialStore.setCredential(subjectId, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> credentialStore.setCredential(subjectId, new char[0]))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> credentialStore.verifyCredential(null, "pass".toCharArray()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> credentialStore.verifyCredential(subjectId, null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> credentialStore.verifyCredential(subjectId, new char[0]))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> credentialStore.verifyDummy(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> credentialStore.verifyDummy(new char[0]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("expired lockout resets attempt counter so first wrong attempt does not immediately re-lock")
    void expiredLockoutResetsCounterOnWrongAttempt() {
        UUID subjectId = UUID.randomUUID();
        credentialStore.setCredential(subjectId, "correctPassword".toCharArray());

        // Simulate expired lockout: 5 failed attempts with lockedUntil in past
        Instant pastLockout = Instant.now().minusSeconds(60);
        repository.recordFailedLogin(subjectId, 5, pastLockout, Instant.now().minusSeconds(100));

        // Wrong password should reset base attempts to 0 and record 1 attempt, NOT re-lock immediately!
        CredentialVerificationResult result = credentialStore.verifyCredential(subjectId, "wrongPassword".toCharArray());
        assertThat(result.isInvalid()).isTrue();
        assertThat(result.isLocked()).isFalse();

        LockoutState state = credentialStore.getLockoutState(subjectId);
        assertThat(state.failedAttempts()).isEqualTo(1);
        assertThat(state.isLocked(Instant.now())).isFalse();
    }

    @Test
    @DisplayName("changePassword throws AccountLockedException when account is actively locked")
    void changePasswordWhileLockedThrows() {
        UUID subjectId = UUID.randomUUID();
        credentialStore.setCredential(subjectId, "OldPassword123!".toCharArray());

        // Lock the account
        Instant futureLockout = Instant.now().plusSeconds(600);
        repository.recordFailedLogin(subjectId, 5, futureLockout, Instant.now());

        assertThatThrownBy(() -> credentialStore.changePassword(
                subjectId,
                "OldPassword123!".toCharArray(),
                "NewPassword456!".toCharArray()
        )).isInstanceOf(AccountLockedException.class)
          .satisfies(ex -> {
              AccountLockedException ale = (AccountLockedException) ex;
              assertThat(ale.lockedUntil()).isEqualTo(futureLockout);
          });
    }

    @Test
    @DisplayName("changePassword with wrong current password tracks failed attempts and locks out at threshold")
    void changePasswordTracksFailedAttemptsAndLocks() {
        UUID subjectId = UUID.randomUUID();
        credentialStore.setCredential(subjectId, "OldPassword123!".toCharArray());

        for (int i = 1; i <= 4; i++) {
            assertThatThrownBy(() -> credentialStore.changePassword(
                    subjectId,
                    "WrongCurrent!".toCharArray(),
                    "NewPassword456!".toCharArray()
            )).isInstanceOf(InvalidCredentialException.class);

            assertThat(credentialStore.getLockoutState(subjectId).failedAttempts()).isEqualTo(i);
        }

        // 5th failed changePassword attempt triggers AccountLockedException
        assertThatThrownBy(() -> credentialStore.changePassword(
                subjectId,
                "WrongCurrent!".toCharArray(),
                "NewPassword456!".toCharArray()
        )).isInstanceOf(AccountLockedException.class);

        assertThat(credentialStore.getLockoutState(subjectId).isLocked(Instant.now())).isTrue();
    }
}
