package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.AccountVerification;
import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.credentialstore.internal.audit.AuditTrailBridge;
import eu.exeris.caps.credentialstore.internal.crypto.SingleUseHashedToken;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRecord;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRepository;
import eu.exeris.caps.credentialstore.spi.NotificationDispatcher;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default implementation of {@link AccountVerification}. A token is only ever sent to the login identifier
 * stored with the credential, never to an address the caller supplies.
 *
 * <p>{@link #issueVerification} returns the same way whether or not the account exists: a failure of the
 * notification dispatcher is logged, not thrown, so it cannot be told apart from an unknown login by the
 * caller. Response time still differs, because a known account costs a write and a dispatch.
 */
public final class DefaultAccountVerification implements AccountVerification {

    private static final System.Logger LOG = System.getLogger(DefaultAccountVerification.class.getName());

    private final CredentialRepository repository;
    private final NotificationDispatcher notificationDispatcher;
    private final AuditTrailBridge auditTrail;
    private final TokenPolicy tokenPolicy;
    private final Clock clock;

    public DefaultAccountVerification(
            CredentialRepository repository,
            NotificationDispatcher notificationDispatcher,
            AuditTrailBridge auditTrail,
            TokenPolicy tokenPolicy,
            Clock clock
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.notificationDispatcher = Objects.requireNonNull(notificationDispatcher, "notificationDispatcher must not be null");
        this.auditTrail = auditTrail;
        this.tokenPolicy = Objects.requireNonNull(tokenPolicy, "tokenPolicy must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public void issueVerification(String loginIdentifier) {
        String login = LoginIdentifiers.normalize(loginIdentifier);
        Optional<CredentialRecord> credential = repository.findByLoginIdentifier(login);
        if (credential.isEmpty() || credential.get().emailVerified()) {
            return;
        }
        UUID subjectId = credential.get().subjectId();
        Instant now = clock.instant();
        SingleUseHashedToken.GeneratedToken token = SingleUseHashedToken.generate();
        boolean issued = repository.issueVerificationToken(
                UUID.randomUUID(), subjectId, token.tokenHash(),
                now.plus(tokenPolicy.verificationValidity()), now, now.minus(tokenPolicy.issueCooldown()));
        if (!issued) {
            return;
        }
        boolean delivered = true;
        try {
            notificationDispatcher.sendVerificationToken(subjectId, credential.get().loginIdentifier(), token.rawToken());
        } catch (RuntimeException e) {
            delivered = false;
            LOG.log(System.Logger.Level.WARNING,
                    "verification token for subject " + subjectId + " was not delivered: " + e.getClass().getName(), e);
        }
        if (auditTrail != null) {
            auditTrail.emit("VERIFICATION_ISSUED", subjectId, Map.of("delivered", delivered));
        }
    }

    @Override
    public UUID verifyAccount(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be null or blank");
        }
        UUID subjectId = repository.consumeVerificationToken(SingleUseHashedToken.hashToken(rawToken), clock.instant())
                .orElseThrow(() -> new InvalidTokenException("Verification token is invalid or expired"));
        if (auditTrail != null) {
            auditTrail.emit("ACCOUNT_VERIFIED", subjectId, Map.of());
        }
        return subjectId;
    }
}
