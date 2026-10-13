package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.AccountVerification;
import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.exception.TokenCooldownException;
import eu.exeris.caps.credentialstore.internal.audit.AuditTrailBridge;
import eu.exeris.caps.credentialstore.internal.crypto.SingleUseHashedToken;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRepository;
import eu.exeris.caps.credentialstore.internal.repository.TokenRecord;
import eu.exeris.caps.credentialstore.spi.NotificationDispatcher;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default implementation of {@link AccountVerification}.
 */
public final class DefaultAccountVerification implements AccountVerification {

    private static final Duration DEFAULT_COOLDOWN = Duration.ofSeconds(60);
    private static final Duration DEFAULT_VALIDITY = Duration.ofHours(24);

    private final CredentialRepository repository;
    private final NotificationDispatcher notificationDispatcher;
    private final AuditTrailBridge auditTrail;
    private final Duration cooldownDuration;
    private final Duration validityDuration;

    public DefaultAccountVerification(
            CredentialRepository repository,
            NotificationDispatcher notificationDispatcher,
            AuditTrailBridge auditTrail
    ) {
        this(repository, notificationDispatcher, auditTrail, DEFAULT_COOLDOWN, DEFAULT_VALIDITY);
    }

    public DefaultAccountVerification(
            CredentialRepository repository,
            NotificationDispatcher notificationDispatcher,
            AuditTrailBridge auditTrail,
            Duration cooldownDuration,
            Duration validityDuration
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.notificationDispatcher = Objects.requireNonNull(notificationDispatcher, "notificationDispatcher must not be null");
        this.auditTrail = auditTrail;
        this.cooldownDuration = Objects.requireNonNull(cooldownDuration, "cooldownDuration must not be null");
        this.validityDuration = Objects.requireNonNull(validityDuration, "validityDuration must not be null");
    }

    @Override
    public void issueVerification(UUID subjectId, String recipientEmail) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        if (recipientEmail == null || recipientEmail.isBlank()) {
            throw new IllegalArgumentException("recipientEmail must not be null or blank");
        }

        Instant now = Instant.now();
        Optional<TokenRecord> latest = repository.findLatestVerificationToken(subjectId);
        if (latest.isPresent()) {
            Duration elapsed = Duration.between(latest.get().createdAt(), now);
            if (elapsed.compareTo(cooldownDuration) < 0) {
                Duration remaining = cooldownDuration.minus(elapsed);
                throw new TokenCooldownException("Verification token request is on cooldown", remaining);
            }
        }

        SingleUseHashedToken.GeneratedToken token = SingleUseHashedToken.generate();
        UUID tokenId = UUID.randomUUID();
        Instant expiresAt = now.plus(validityDuration);

        repository.saveVerificationToken(tokenId, subjectId, token.tokenHash(), expiresAt, now);
        notificationDispatcher.sendVerificationToken(subjectId, recipientEmail, token.rawToken());

        if (auditTrail != null) {
            auditTrail.emit("VERIFICATION_ISSUED", subjectId, Map.of("recipientEmail", recipientEmail));
        }
    }

    @Override
    public UUID verifyAccount(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be null or blank");
        }

        String hash = SingleUseHashedToken.hashToken(rawToken);
        TokenRecord record = repository.findVerificationTokenByHash(hash)
                .orElseThrow(() -> new InvalidTokenException("Verification token not found or invalid"));

        Instant now = Instant.now();
        if (record.expiresAt().isBefore(now)) {
            throw new InvalidTokenException("Verification token has expired");
        }
        if (record.consumedAt() != null) {
            throw new InvalidTokenException("Verification token has already been consumed");
        }

        boolean consumed = repository.consumeVerificationToken(record.id(), now);
        if (!consumed) {
            throw new InvalidTokenException("Verification token has already been consumed (double-spend detected)");
        }

        repository.setEmailVerified(record.subjectId(), now);

        if (auditTrail != null) {
            auditTrail.emit("ACCOUNT_VERIFIED", record.subjectId(), Map.of());
        }

        return record.subjectId();
    }
}
