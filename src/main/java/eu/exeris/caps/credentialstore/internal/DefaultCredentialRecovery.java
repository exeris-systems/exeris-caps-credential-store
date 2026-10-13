package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.CredentialRecovery;
import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.credentialstore.internal.audit.AuditTrailBridge;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.internal.crypto.SingleUseHashedToken;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRecord;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRepository;
import eu.exeris.caps.credentialstore.internal.repository.TokenRecord;
import eu.exeris.caps.credentialstore.spi.NotificationDispatcher;
import eu.exeris.caps.credentialstore.spi.SessionStore;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;

/**
 * Default implementation of {@link CredentialRecovery}.
 *
 * <p>The new hash is derived before the token is touched, and the token is consumed in the same transaction
 * that writes the hash, so a failure at any step leaves both the token and the password as they were.
 */
public final class DefaultCredentialRecovery implements CredentialRecovery {

    private final CredentialRepository repository;
    private final PasswordHashing hashing;
    private final NotificationDispatcher notificationDispatcher;
    private final SessionStore sessionStore;
    private final AuditTrailBridge auditTrail;
    private final TokenPolicy tokenPolicy;
    private final Clock clock;

    public DefaultCredentialRecovery(
            CredentialRepository repository,
            PasswordHashing hashing,
            NotificationDispatcher notificationDispatcher,
            SessionStore sessionStore,
            AuditTrailBridge auditTrail,
            TokenPolicy tokenPolicy,
            Clock clock
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.hashing = Objects.requireNonNull(hashing, "hashing must not be null");
        this.notificationDispatcher = Objects.requireNonNull(notificationDispatcher, "notificationDispatcher must not be null");
        this.sessionStore = sessionStore;
        this.auditTrail = auditTrail;
        this.tokenPolicy = Objects.requireNonNull(tokenPolicy, "tokenPolicy must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public void requestReset(String loginIdentifier) {
        String login = LoginIdentifiers.normalize(loginIdentifier);
        Optional<CredentialRecord> record = repository.findByLoginIdentifier(login);
        if (record.isEmpty()) {
            return;
        }
        UUID subjectId = record.get().subjectId();
        Instant now = clock.instant();
        SingleUseHashedToken.GeneratedToken token = SingleUseHashedToken.generate();
        boolean issued = repository.issueResetToken(
                UUID.randomUUID(), subjectId, token.tokenHash(),
                now.plus(tokenPolicy.resetValidity()), now, now.minus(tokenPolicy.issueCooldown()));
        if (!issued) {
            return;
        }
        notificationDispatcher.sendPasswordResetToken(subjectId, record.get().loginIdentifier(), token.rawToken());
        audit("RESET_REQUESTED", subjectId, Map.of());
    }

    @Override
    public void consumeReset(String rawToken, char[] newPassword) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be null or blank");
        }
        DefaultCredentialStore.requirePassword(newPassword, "newPassword");

        String tokenHash = SingleUseHashedToken.hashToken(rawToken);
        Instant now = clock.instant();
        TokenRecord token = repository.findResetToken(tokenHash)
                .filter(t -> t.usableAt(now))
                .orElseThrow(DefaultCredentialRecovery::invalidToken);
        CredentialRecord record = repository.findBySubject(token.subjectId())
                .orElseThrow(DefaultCredentialRecovery::invalidToken);

        if (hashing.matches(newPassword, record.passwordHash())) {
            throw new SamePasswordException("New password cannot be identical to current password");
        }
        String newHash = hashing.encode(newPassword);

        OptionalLong tokenVersion = repository.consumeResetToken(tokenHash, newHash, clock.instant());
        if (tokenVersion.isEmpty()) {
            throw invalidToken();
        }
        if (sessionStore != null) {
            sessionStore.revokeAllForSubject(token.subjectId());
        }
        audit("PASSWORD_RESET", token.subjectId(), Map.of("tokenVersion", tokenVersion.getAsLong()));
    }

    private static InvalidTokenException invalidToken() {
        return new InvalidTokenException("Reset token is invalid or expired");
    }

    private void audit(String action, UUID subjectId, Map<String, Object> details) {
        if (auditTrail != null) {
            auditTrail.emit(action, subjectId, details);
        }
    }
}
