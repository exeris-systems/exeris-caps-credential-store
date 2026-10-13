package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.CredentialStore;
import eu.exeris.caps.credentialstore.api.exception.AccountLockedException;
import eu.exeris.caps.credentialstore.api.exception.CredentialAlreadyExistsException;
import eu.exeris.caps.credentialstore.api.exception.InvalidCredentialException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.model.CredentialVerificationResult;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.LockoutState;
import eu.exeris.caps.credentialstore.internal.audit.AuditTrailBridge;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRecord;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRepository;
import eu.exeris.caps.credentialstore.spi.SessionStore;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;

/**
 * Default implementation of {@link CredentialStore}.
 *
 * <p>A password check reserves a lockout attempt before the key derivation and runs the derivation against
 * the hash the reservation returned, so neither a concurrent burst of guesses nor a concurrent password
 * change can slip between the lockout decision and the comparison. An unknown login, and a refused
 * reservation, run a derivation too.
 */
public final class DefaultCredentialStore implements CredentialStore {

    private final CredentialRepository repository;
    private final PasswordHashing hashing;
    private final LockoutPolicy lockoutPolicy;
    private final SessionStore sessionStore;
    private final AuditTrailBridge auditTrail;
    private final Clock clock;

    public DefaultCredentialStore(
            CredentialRepository repository,
            PasswordHashing hashing,
            LockoutPolicy lockoutPolicy,
            SessionStore sessionStore,
            AuditTrailBridge auditTrail,
            Clock clock
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.hashing = Objects.requireNonNull(hashing, "hashing must not be null");
        this.lockoutPolicy = Objects.requireNonNull(lockoutPolicy, "lockoutPolicy must not be null");
        this.sessionStore = sessionStore;
        this.auditTrail = auditTrail;
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public void createCredential(UUID subjectId, String loginIdentifier, char[] password) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        String login = LoginIdentifiers.normalize(loginIdentifier);
        requirePassword(password, "password");

        String hash = hashing.encode(password);
        if (!repository.insertCredential(subjectId, login, hash, clock.instant())) {
            throw new CredentialAlreadyExistsException();
        }
        audit("CREDENTIAL_CREATED", subjectId, Map.of());
    }

    @Override
    public CredentialVerificationResult authenticate(String loginIdentifier, char[] password) {
        String login = LoginIdentifiers.normalize(loginIdentifier);
        requirePassword(password, "password");
        Optional<CredentialRecord> record = repository.findByLoginIdentifier(login);
        if (record.isEmpty()) {
            hashing.burn(password);
            return CredentialVerificationResult.invalid();
        }
        return check(record.get().subjectId(), password);
    }

    @Override
    public CredentialVerificationResult verifyCredential(UUID subjectId, char[] password) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        requirePassword(password, "password");
        return check(subjectId, password);
    }

    private CredentialVerificationResult check(UUID subjectId, char[] password) {
        Instant now = clock.instant();
        Optional<CredentialRecord> reserved = repository.reserveAttempt(subjectId, lockoutPolicy, now);
        if (reserved.isEmpty()) {
            hashing.burn(password);
            return activeLockout(subjectId, now)
                    .map(CredentialVerificationResult::locked)
                    .orElseGet(CredentialVerificationResult::invalid);
        }
        CredentialRecord record = reserved.get();
        if (!hashing.matches(password, record.passwordHash())) {
            Optional<Instant> lockedUntil = repository.lockIfExhausted(subjectId, lockoutPolicy, now);
            if (lockedUntil.isPresent()) {
                audit("ACCOUNT_LOCKED", subjectId, Map.of("lockedUntil", lockedUntil.get().toString()));
                return CredentialVerificationResult.locked(lockedUntil.get());
            }
            audit("AUTH_FAILURE", subjectId, Map.of("failedAttempts", record.failedLoginAttempts()));
            return CredentialVerificationResult.invalid();
        }

        repository.clearFailures(subjectId, now);
        if (!record.emailVerified()) {
            audit("AUTH_UNVERIFIED", subjectId, Map.of());
            return CredentialVerificationResult.unverified(subjectId);
        }
        if (hashing.needsRehash(record.passwordHash())) {
            repository.replacePasswordHash(subjectId, record.passwordHash(), hashing.encode(password), now);
        }
        audit("AUTH_SUCCESS", subjectId, Map.of());
        return CredentialVerificationResult.success(subjectId);
    }

    @Override
    public void changePassword(UUID subjectId, char[] currentPassword, char[] newPassword) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        requirePassword(currentPassword, "currentPassword");
        requirePassword(newPassword, "newPassword");

        Instant now = clock.instant();
        Optional<CredentialRecord> reserved = repository.reserveAttempt(subjectId, lockoutPolicy, now);
        if (reserved.isEmpty()) {
            hashing.burn(currentPassword);
            Optional<Instant> lockedUntil = activeLockout(subjectId, now);
            if (lockedUntil.isPresent()) {
                throw new AccountLockedException("Account is locked", lockedUntil.get());
            }
            throw new InvalidCredentialException("Current password does not match");
        }
        CredentialRecord record = reserved.get();
        if (!hashing.matches(currentPassword, record.passwordHash())) {
            Optional<Instant> lockedUntil = repository.lockIfExhausted(subjectId, lockoutPolicy, now);
            if (lockedUntil.isPresent()) {
                audit("ACCOUNT_LOCKED", subjectId, Map.of("lockedUntil", lockedUntil.get().toString()));
                throw new AccountLockedException("Account is locked", lockedUntil.get());
            }
            audit("AUTH_FAILURE", subjectId, Map.of("failedAttempts", record.failedLoginAttempts()));
            throw new InvalidCredentialException("Current password does not match");
        }
        repository.clearFailures(subjectId, now);
        if (hashing.matches(newPassword, record.passwordHash())) {
            throw new SamePasswordException("New password cannot be identical to current password");
        }

        String newHash = hashing.encode(newPassword);
        OptionalLong tokenVersion = repository.changePassword(subjectId, record.passwordHash(), newHash, now);
        if (tokenVersion.isEmpty()) {
            throw new InvalidCredentialException("Current password does not match");
        }
        if (sessionStore != null) {
            sessionStore.revokeAllForSubject(subjectId);
        }
        audit("PASSWORD_CHANGED", subjectId, Map.of("tokenVersion", tokenVersion.getAsLong()));
    }

    @Override
    public void clearLockout(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        repository.clearFailures(subjectId, clock.instant());
        audit("LOCKOUT_CLEARED", subjectId, Map.of());
    }

    @Override
    public long getTokenVersion(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        return repository.findBySubject(subjectId).map(CredentialRecord::tokenVersion).orElse(1L);
    }

    @Override
    public boolean isVerified(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        return repository.findBySubject(subjectId).map(CredentialRecord::emailVerified).orElse(false);
    }

    @Override
    public LockoutState getLockoutState(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        return repository.findBySubject(subjectId)
                .map(r -> new LockoutState(r.failedLoginAttempts(), r.lockedUntil()))
                .orElseGet(() -> LockoutState.unlocked(0));
    }

    private Optional<Instant> activeLockout(UUID subjectId, Instant now) {
        return repository.findBySubject(subjectId)
                .map(CredentialRecord::lockedUntil)
                .filter(until -> until.isAfter(now));
    }

    private void audit(String action, UUID subjectId, Map<String, Object> details) {
        if (auditTrail != null) {
            auditTrail.emit(action, subjectId, details);
        }
    }

    static void requirePassword(char[] password, String name) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException(name + " must not be null or empty");
        }
    }
}
