package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.CredentialRecovery;
import eu.exeris.caps.credentialstore.api.exception.InvalidCredentialException;
import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.exception.TokenCooldownException;
import eu.exeris.caps.credentialstore.internal.audit.AuditTrailBridge;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.SingleUseHashedToken;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRecord;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRepository;
import eu.exeris.caps.credentialstore.internal.repository.TokenRecord;
import eu.exeris.caps.credentialstore.spi.NotificationDispatcher;
import eu.exeris.caps.credentialstore.spi.SessionStore;
import eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default implementation of {@link CredentialRecovery}.
 */
public final class DefaultCredentialRecovery implements CredentialRecovery {

    private static final Duration DEFAULT_COOLDOWN = Duration.ofSeconds(60);
    private static final Duration DEFAULT_VALIDITY = Duration.ofMinutes(15);

    private final CredentialRepository repository;
    private final KernelPasswordEncoder passwordEncoder;
    private final KdfConcurrencyThrottler throttler;
    private final NotificationDispatcher notificationDispatcher;
    private final SessionStore sessionStore;
    private final AuditTrailBridge auditTrail;
    private final Duration cooldownDuration;
    private final Duration validityDuration;

    public DefaultCredentialRecovery(
            CredentialRepository repository,
            KernelPasswordEncoder passwordEncoder,
            KdfConcurrencyThrottler throttler,
            NotificationDispatcher notificationDispatcher,
            SessionStore sessionStore,
            AuditTrailBridge auditTrail
    ) {
        this(repository, passwordEncoder, throttler, notificationDispatcher, sessionStore, auditTrail,
                DEFAULT_COOLDOWN, DEFAULT_VALIDITY);
    }

    public DefaultCredentialRecovery(
            CredentialRepository repository,
            KernelPasswordEncoder passwordEncoder,
            KdfConcurrencyThrottler throttler,
            NotificationDispatcher notificationDispatcher,
            SessionStore sessionStore,
            AuditTrailBridge auditTrail,
            Duration cooldownDuration,
            Duration validityDuration
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.passwordEncoder = Objects.requireNonNull(passwordEncoder, "passwordEncoder must not be null");
        this.throttler = Objects.requireNonNull(throttler, "throttler must not be null");
        this.notificationDispatcher = Objects.requireNonNull(notificationDispatcher, "notificationDispatcher must not be null");
        this.sessionStore = sessionStore;
        this.auditTrail = auditTrail;
        this.cooldownDuration = Objects.requireNonNull(cooldownDuration, "cooldownDuration must not be null");
        this.validityDuration = Objects.requireNonNull(validityDuration, "validityDuration must not be null");
    }

    @Override
    public void requestReset(UUID subjectId, String recipientEmail) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        if (recipientEmail == null || recipientEmail.isBlank()) {
            throw new IllegalArgumentException("recipientEmail must not be null or blank");
        }

        Instant now = Instant.now();
        Optional<TokenRecord> latest = repository.findLatestResetToken(subjectId);
        if (latest.isPresent()) {
            Duration elapsed = Duration.between(latest.get().createdAt(), now);
            if (elapsed.compareTo(cooldownDuration) < 0) {
                Duration remaining = cooldownDuration.minus(elapsed);
                throw new TokenCooldownException("Reset token request is on cooldown", remaining);
            }
        }

        SingleUseHashedToken.GeneratedToken token = SingleUseHashedToken.generate();
        UUID tokenId = UUID.randomUUID();
        Instant expiresAt = now.plus(validityDuration);

        repository.saveResetToken(tokenId, subjectId, token.tokenHash(), expiresAt, now);
        notificationDispatcher.sendPasswordResetToken(subjectId, recipientEmail, token.rawToken());

        if (auditTrail != null) {
            auditTrail.emit("RESET_REQUESTED", subjectId, Map.of("recipientEmail", recipientEmail));
        }
    }

    @Override
    public void consumeReset(String rawToken, char[] newPassword) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be null or blank");
        }
        if (newPassword == null || newPassword.length == 0) {
            throw new IllegalArgumentException("newPassword must not be null or empty");
        }

        String hash = SingleUseHashedToken.hashToken(rawToken);
        TokenRecord token = repository.findResetTokenByHash(hash)
                .orElseThrow(() -> new InvalidTokenException("Reset token not found or invalid"));

        Instant now = Instant.now();
        if (token.expiresAt().isBefore(now)) {
            throw new InvalidTokenException("Reset token has expired");
        }
        if (token.consumedAt() != null) {
            throw new InvalidTokenException("Reset token has already been consumed");
        }

        CredentialRecord record = repository.findCredential(token.subjectId())
                .orElseThrow(() -> new InvalidCredentialException("Credential not found for subject: " + token.subjectId()));

        char[] newCopy = Arrays.copyOf(newPassword, newPassword.length);
        try {
            boolean samePassword = throttler.execute(() -> passwordEncoder.matches(newCopy, record.passwordHash()));
            if (samePassword) {
                throw new SamePasswordException("New password cannot be identical to current password");
            }

            // Compute new password hash before consuming token to avoid burning token on failure
            String newHash = throttler.execute(() -> passwordEncoder.encode(newCopy));

            boolean consumed = repository.consumeResetToken(token.id(), now);
            if (!consumed) {
                throw new InvalidTokenException("Reset token has already been consumed (double-spend detected)");
            }

            long newTokenVersion = record.tokenVersion() + 1;
            repository.updatePassword(token.subjectId(), newHash, newTokenVersion, now);

            if (sessionStore != null) {
                sessionStore.revokeAllForSubject(token.subjectId());
            }
            if (auditTrail != null) {
                auditTrail.emit("PASSWORD_RESET", token.subjectId(), Map.of("tokenVersion", newTokenVersion));
            }
        } finally {
            Arrays.fill(newCopy, '\0');
        }
    }
}
