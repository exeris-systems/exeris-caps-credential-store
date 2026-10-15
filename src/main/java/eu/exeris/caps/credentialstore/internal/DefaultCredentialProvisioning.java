package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.CredentialProvisioning;
import eu.exeris.caps.credentialstore.api.exception.CredentialAlreadyExistsException;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.api.model.ProvisionResult;
import eu.exeris.caps.credentialstore.internal.audit.AuditTrailBridge;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRepository;

import java.time.Clock;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Default implementation of {@link CredentialProvisioning}.
 *
 * <p>Provisions a verified credential in one transaction, zeroes the supplied password array, and emits a
 * {@code CREDENTIAL_PROVISIONED} audit event after commit.
 */
public final class DefaultCredentialProvisioning implements CredentialProvisioning {

    private static final String PASSWORD_PARAM = "password";

    private final CredentialRepository repository;
    private final PasswordHashing hashing;
    private final PasswordPolicy passwordPolicy;
    private final AuditTrailBridge auditTrail;
    private final Clock clock;

    public DefaultCredentialProvisioning(
            CredentialRepository repository,
            PasswordHashing hashing,
            PasswordPolicy passwordPolicy,
            AuditTrailBridge auditTrail,
            Clock clock
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.hashing = Objects.requireNonNull(hashing, "hashing must not be null");
        this.passwordPolicy = Objects.requireNonNull(passwordPolicy, "passwordPolicy must not be null");
        this.auditTrail = auditTrail;
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public ProvisionResult provisionVerified(UUID subjectId, String loginIdentifier, char[] password) {
        try {
            Objects.requireNonNull(subjectId, "subjectId must not be null");
            String login = LoginIdentifiers.normalize(loginIdentifier);
            DefaultCredentialStore.requireNewPassword(passwordPolicy, password, PASSWORD_PARAM);

            String hash = hashing.encode(password);
            if (!repository.insertVerifiedCredential(subjectId, login, hash, clock.instant())) {
                throw new CredentialAlreadyExistsException();
            }
            if (auditTrail != null) {
                auditTrail.emit("CREDENTIAL_PROVISIONED", subjectId, Map.of());
            }
            return new ProvisionResult(subjectId, login);
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }
}
