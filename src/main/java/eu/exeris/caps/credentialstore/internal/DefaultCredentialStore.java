package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.CredentialStore;
import eu.exeris.caps.credentialstore.api.exception.AccountLockedException;
import eu.exeris.caps.credentialstore.api.exception.InvalidCredentialException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.RehashablePasswordEncoder;
import eu.exeris.caps.credentialstore.api.model.CredentialVerificationResult;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.LockoutState;
import eu.exeris.caps.credentialstore.internal.audit.AuditTrailBridge;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRecord;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRepository;
import eu.exeris.caps.credentialstore.spi.SessionStore;
import eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder;

import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default implementation of {@link CredentialStore}.
 *
 * <p>Isolates DB connection holds from expensive Argon2id derivations via {@link KdfConcurrencyThrottler},
 * wipes sensitive password char buffers, and cascades session revocation on password changes.
 */
public final class DefaultCredentialStore implements CredentialStore {

    private final CredentialRepository repository;
    private final KernelPasswordEncoder passwordEncoder;
    private final KdfConcurrencyThrottler throttler;
    private final LockoutPolicy lockoutPolicy;
    private final SessionStore sessionStore;
    private final AuditTrailBridge auditTrail;
    private final String dummyPasswordHash;

    public DefaultCredentialStore(
            CredentialRepository repository,
            KernelPasswordEncoder passwordEncoder,
            KdfConcurrencyThrottler throttler,
            LockoutPolicy lockoutPolicy,
            SessionStore sessionStore,
            AuditTrailBridge auditTrail
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.passwordEncoder = Objects.requireNonNull(passwordEncoder, "passwordEncoder must not be null");
        this.throttler = Objects.requireNonNull(throttler, "throttler must not be null");
        this.lockoutPolicy = Objects.requireNonNull(lockoutPolicy, "lockoutPolicy must not be null");
        this.sessionStore = sessionStore;
        this.auditTrail = auditTrail;

        char[] dummy = "ExerisDummyPass$123".toCharArray();
        try {
            this.dummyPasswordHash = this.throttler.execute(() -> this.passwordEncoder.encode(dummy));
        } finally {
            Arrays.fill(dummy, '\0');
        }
    }

    @Override
    public void setCredential(UUID subjectId, char[] newPassword) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        if (newPassword == null || newPassword.length == 0) {
            throw new IllegalArgumentException("newPassword must not be null or empty");
        }
        char[] copy = Arrays.copyOf(newPassword, newPassword.length);
        try {
            String hash = throttler.execute(() -> passwordEncoder.encode(copy));
            repository.saveCredential(subjectId, hash, Instant.now());
            if (auditTrail != null) {
                auditTrail.emit("CREDENTIAL_SET", subjectId, Map.of());
            }
        } finally {
            Arrays.fill(copy, '\0');
        }
    }

    @Override
    public CredentialVerificationResult verifyCredential(UUID subjectId, char[] candidatePassword) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        if (candidatePassword == null || candidatePassword.length == 0) {
            throw new IllegalArgumentException("candidatePassword must not be null or empty");
        }

        Optional<CredentialRecord> opt = repository.findCredential(subjectId);
        if (opt.isEmpty()) {
            return CredentialVerificationResult.invalid();
        }

        CredentialRecord record = opt.get();
        Instant now = Instant.now();

        // Check active lockout
        if (record.lockedUntil() != null && record.lockedUntil().isAfter(now)) {
            return CredentialVerificationResult.locked(record.lockedUntil());
        }

        char[] copy = Arrays.copyOf(candidatePassword, candidatePassword.length);
        boolean matches;
        try {
            matches = throttler.execute(() -> passwordEncoder.matches(copy, record.passwordHash()));
        } finally {
            Arrays.fill(copy, '\0');
        }

        if (matches) {
            if (record.failedLoginAttempts() > 0 || record.lockedUntil() != null) {
                repository.unlockAccount(subjectId, now);
            }
            if (auditTrail != null) {
                auditTrail.emit("AUTH_SUCCESS", subjectId, Map.of());
            }
            if (passwordEncoder instanceof RehashablePasswordEncoder rehashable
                    && rehashable.needsRehash(record.passwordHash())) {
                char[] rehashCopy = Arrays.copyOf(candidatePassword, candidatePassword.length);
                try {
                    String upgradedHash = throttler.execute(() -> passwordEncoder.encode(rehashCopy));
                    repository.saveCredential(subjectId, upgradedHash, now);
                } finally {
                    Arrays.fill(rehashCopy, '\0');
                }
            }
            return CredentialVerificationResult.success();
        } else {
            int currentFailed = (record.lockedUntil() != null && !record.lockedUntil().isAfter(now))
                    ? 0
                    : record.failedLoginAttempts();
            int newAttempts = currentFailed + 1;
            if (newAttempts >= lockoutPolicy.maxAttempts()) {
                Instant lockedUntil = now.plus(lockoutPolicy.lockoutDuration());
                repository.recordFailedLogin(subjectId, newAttempts, lockedUntil, now);
                if (auditTrail != null) {
                    auditTrail.emit("ACCOUNT_LOCKED", subjectId, Map.of(
                            "failedAttempts", newAttempts,
                            "lockedUntil", lockedUntil.toString()
                    ));
                }
                return CredentialVerificationResult.locked(lockedUntil);
            } else {
                repository.recordFailedLogin(subjectId, newAttempts, null, now);
                if (auditTrail != null) {
                    auditTrail.emit("AUTH_FAILURE", subjectId, Map.of("failedAttempts", newAttempts));
                }
                return CredentialVerificationResult.invalid();
            }
        }
    }

    @Override
    public void verifyDummy(char[] candidatePassword) {
        if (candidatePassword == null || candidatePassword.length == 0) {
            throw new IllegalArgumentException("candidatePassword must not be null or empty");
        }
        char[] copy = Arrays.copyOf(candidatePassword, candidatePassword.length);
        try {
            throttler.execute(() -> passwordEncoder.matches(copy, dummyPasswordHash));
        } finally {
            Arrays.fill(copy, '\0');
        }
    }

    @Override
    public void changePassword(UUID subjectId, char[] currentPassword, char[] newPassword) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        if (currentPassword == null || currentPassword.length == 0) {
            throw new IllegalArgumentException("currentPassword must not be null or empty");
        }
        if (newPassword == null || newPassword.length == 0) {
            throw new IllegalArgumentException("newPassword must not be null or empty");
        }

        CredentialRecord record = repository.findCredential(subjectId)
                .orElseThrow(() -> new InvalidCredentialException("Credential not found for subject: " + subjectId));

        Instant now = Instant.now();
        if (record.lockedUntil() != null && record.lockedUntil().isAfter(now)) {
            throw new AccountLockedException("Account is locked until " + record.lockedUntil(), record.lockedUntil());
        }

        char[] currentCopy = Arrays.copyOf(currentPassword, currentPassword.length);
        char[] newCopy = Arrays.copyOf(newPassword, newPassword.length);
        try {
            boolean currentMatches = throttler.execute(() -> passwordEncoder.matches(currentCopy, record.passwordHash()));
            if (!currentMatches) {
                int currentFailed = (record.lockedUntil() != null && !record.lockedUntil().isAfter(now))
                        ? 0
                        : record.failedLoginAttempts();
                int newAttempts = currentFailed + 1;
                if (newAttempts >= lockoutPolicy.maxAttempts()) {
                    Instant lockedUntil = now.plus(lockoutPolicy.lockoutDuration());
                    repository.recordFailedLogin(subjectId, newAttempts, lockedUntil, now);
                    if (auditTrail != null) {
                        auditTrail.emit("ACCOUNT_LOCKED", subjectId, Map.of(
                                "failedAttempts", newAttempts,
                                "lockedUntil", lockedUntil.toString()
                        ));
                    }
                    throw new AccountLockedException("Account locked due to excessive failed attempts", lockedUntil);
                } else {
                    repository.recordFailedLogin(subjectId, newAttempts, null, now);
                    if (auditTrail != null) {
                        auditTrail.emit("AUTH_FAILURE", subjectId, Map.of("failedAttempts", newAttempts));
                    }
                    throw new InvalidCredentialException("Current password does not match");
                }
            }

            boolean samePassword = throttler.execute(() -> passwordEncoder.matches(newCopy, record.passwordHash()));
            if (samePassword) {
                throw new SamePasswordException("New password cannot be identical to current password");
            }

            String newHash = throttler.execute(() -> passwordEncoder.encode(newCopy));
            long newTokenVersion = record.tokenVersion() + 1;
            repository.updatePassword(subjectId, newHash, newTokenVersion, now);

            if (sessionStore != null) {
                sessionStore.revokeAllForSubject(subjectId);
            }
            if (auditTrail != null) {
                auditTrail.emit("PASSWORD_CHANGED", subjectId, Map.of("tokenVersion", newTokenVersion));
            }
        } finally {
            Arrays.fill(currentCopy, '\0');
            Arrays.fill(newCopy, '\0');
        }
    }

    @Override
    public void clearLockout(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        repository.unlockAccount(subjectId, Instant.now());
        if (auditTrail != null) {
            auditTrail.emit("LOCKOUT_CLEARED", subjectId, Map.of());
        }
    }

    @Override
    public long getTokenVersion(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        return repository.getTokenVersion(subjectId);
    }

    @Override
    public boolean isVerified(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        return repository.isEmailVerified(subjectId);
    }

    @Override
    public LockoutState getLockoutState(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        return repository.findCredential(subjectId)
                .map(r -> new LockoutState(r.failedLoginAttempts(), r.lockedUntil()))
                .orElseGet(() -> LockoutState.unlocked(0));
    }
}
