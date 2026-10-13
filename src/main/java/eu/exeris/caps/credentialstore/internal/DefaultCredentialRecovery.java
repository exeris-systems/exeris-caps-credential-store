package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.CredentialRecovery;
import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
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
 * that writes the hash. The subject's sessions are revoked before that transaction (see
 * {@link SessionRevocation}), so a failure of the session store, of the derivation or of the write leaves the
 * token usable and the password as it was; a call that reports success has revoked every session that existed
 * when it began.
 */
public final class DefaultCredentialRecovery implements CredentialRecovery {

    private final CredentialRepository repository;
    private final PasswordHashing hashing;
    private final NotificationDispatcher notificationDispatcher;
    private final SessionRevocation sessions;
    private final AuditTrailBridge auditTrail;
    private final TokenPolicy tokenPolicy;
    private final PasswordPolicy passwordPolicy;
    private final Clock clock;

    public DefaultCredentialRecovery(
            CredentialRepository repository,
            PasswordHashing hashing,
            NotificationDispatcher notificationDispatcher,
            SessionStore sessionStore,
            AuditTrailBridge auditTrail,
            TokenPolicy tokenPolicy,
            PasswordPolicy passwordPolicy,
            Clock clock
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.hashing = Objects.requireNonNull(hashing, "hashing must not be null");
        this.notificationDispatcher = Objects.requireNonNull(notificationDispatcher, "notificationDispatcher must not be null");
        this.sessions = new SessionRevocation(sessionStore);
        this.auditTrail = auditTrail;
        this.tokenPolicy = Objects.requireNonNull(tokenPolicy, "tokenPolicy must not be null");
        this.passwordPolicy = Objects.requireNonNull(passwordPolicy, "passwordPolicy must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public void requestReset(String loginIdentifier) {
        String login = LoginIdentifiers.normalize(loginIdentifier);
        Optional<CredentialRecord> credential = repository.findByLoginIdentifier(login);
        if (credential.isEmpty()) {
            return;
        }
        UUID subjectId = credential.get().subjectId();
        Instant now = clock.instant();
        SingleUseHashedToken.GeneratedToken token = SingleUseHashedToken.generate();
        boolean issued = repository.issueResetToken(
                UUID.randomUUID(), subjectId, token.tokenHash(),
                now.plus(tokenPolicy.resetValidity()), now, now.minus(tokenPolicy.issueCooldown()));
        if (!issued) {
            return;
        }
        notificationDispatcher.sendPasswordResetToken(subjectId, credential.get().loginIdentifier(), token.rawToken());
        audit("RESET_REQUESTED", subjectId, Map.of());
    }

    @Override
    public void consumeReset(String rawToken, char[] newPassword) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be null or blank");
        }
        DefaultCredentialStore.requireNewPassword(passwordPolicy, newPassword, "newPassword");

        String tokenHash = SingleUseHashedToken.hashToken(rawToken);
        Instant now = clock.instant();
        TokenRecord token = repository.findResetToken(tokenHash)
                .filter(t -> t.usableAt(now))
                .orElseThrow(DefaultCredentialRecovery::invalidToken);
        CredentialRecord credential = repository.findBySubject(token.subjectId())
                .orElseThrow(DefaultCredentialRecovery::invalidToken);

        if (hashing.matches(newPassword, credential.passwordHash())) {
            throw new SamePasswordException("New password cannot be identical to current password");
        }
        String newHash = hashing.encode(newPassword);

        sessions.beforeWrite(token.subjectId());
        OptionalLong tokenVersion = repository.consumeResetToken(tokenHash, newHash, clock.instant());
        if (tokenVersion.isEmpty()) {
            throw invalidToken();
        }
        sessions.afterWrite(token.subjectId());
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
