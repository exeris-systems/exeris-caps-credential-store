package eu.exeris.caps.credentialstore.api;

import eu.exeris.caps.credentialstore.api.exception.CredentialAlreadyExistsException;
import eu.exeris.caps.credentialstore.api.model.ProvisionResult;

import java.util.UUID;

/**
 * Administrative provisioning of verified credentials for host bootstrap.
 *
 * <p>A host bootstrapping its first operator account uses this service to create a credential that can
 * authenticate immediately, bypassing account verification by design. It must not be used for regular user
 * registration or self-service sign-up.
 *
 * @since 0.1.0
 */
public interface CredentialProvisioning {

    /**
     * Provisions a verified credential for a new account in one transaction, without issuing a verification
     * token.
     *
     * <p>The provided {@code password} array is zeroed upon return.
     *
     * @param subjectId       identifier of the new subject
     * @param loginIdentifier login identifier and notification address of the new account
     * @param password        initial password; zeroed by this method
     * @return the outcome carrying the provisioned subject and normalised login identifier
     * @throws CredentialAlreadyExistsException if the subject or the login identifier already has a
     *                                          credential; nothing is written
     * @throws NullPointerException             if {@code subjectId} is null
     * @throws IllegalArgumentException         if the login identifier is null, blank or not an address, or
     *                                          the password is null, empty or outside the
     *                                          {@code PasswordPolicy} window
     */
    ProvisionResult provisionVerified(UUID subjectId, String loginIdentifier, char[] password);
}
