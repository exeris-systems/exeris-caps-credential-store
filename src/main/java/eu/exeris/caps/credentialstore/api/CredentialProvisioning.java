package eu.exeris.caps.credentialstore.api;

import eu.exeris.caps.credentialstore.api.exception.CredentialAlreadyExistsException;
import eu.exeris.caps.credentialstore.api.model.ProvisionResult;

import java.util.Optional;
import java.util.UUID;

/**
 * Administrative provisioning of verified credentials by a host that has already established ownership of
 * the login address.
 *
 * <p>This service creates a credential that can authenticate immediately, with no verification token,
 * bypassing account verification by design. The host takes responsibility for the precondition: it has
 * established, by its own means, that the caller controls the login address and is entitled to the account.
 * Examples are a first-account bootstrap run by the operator of the deployment, and the acceptance of an
 * invitation whose single-use token was delivered to that address and is consumed in the same transaction.
 * The capability cannot check this precondition and does not try to.
 *
 * <p>It must never serve unauthenticated self-service sign-up, where nothing has proven control of the
 * address. That path is {@link CredentialStore#createCredential}, which creates an unverified credential and
 * issues a verification token.
 *
 * @since 0.1.0
 */
public interface CredentialProvisioning {

    /**
     * Provisions a verified credential for a new account in one transaction, without issuing a verification
     * token.
     *
     * <p>The caller must already have established that the requester controls {@code loginIdentifier} and is
     * entitled to the account; the credential can authenticate as soon as this method returns. The
     * capability cannot verify that, so a caller that has not established it creates a sign-in for an address
     * nobody has proven to own. Use {@link CredentialStore#createCredential} when it has not.
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

    /**
     * Provisions a verified credential only if the deployment holds no credential at all, atomically against
     * every concurrent writer of credentials.
     *
     * <p>The check and the insert run in one unit of work under a table lock that conflicts with every other
     * credential insert or update and with itself, so of two concurrent callers exactly one can observe an
     * empty table; the other waits for the first unit to end and then sees its outcome. Plain reads such as
     * authentication are not blocked. Under a joining executor the lock is held until the host's enclosing
     * transaction ends, so work the host does afterwards commits or rolls back together with the credential.
     *
     * <p>The lock is acquired before the call reads anything. Under a joining executor the isolation level of
     * the host's transaction decides whether that suffices: at {@code READ COMMITTED} the call may follow
     * earlier reads, because every statement takes a new snapshot; at {@code REPEATABLE READ} or
     * {@code SERIALIZABLE} the transaction's snapshot is fixed by its first query, so the call must be the
     * first statement of the transaction, or a caller that waited for the lock can read a snapshot older than
     * the winner's commit and provision a second first credential. The capability cannot detect a violation
     * and does not refuse it.
     *
     * <p>Call this before any other write to the credential table in the same transaction, so two callers
     * cannot each hold a row lock and wait to upgrade it. The database role needs the privilege that
     * {@code LOCK TABLE} requires in this mode, which any role that updates credentials already has.
     *
     * <p>The credential table is deployment-global, so the answer holds for the whole deployment. If the table
     * is subject to row-level security the answer would be per tenant instead, and the call is refused.
     *
     * <p>The provided {@code password} array is zeroed upon return, on every path. Applying the schema
     * migrations is the host's responsibility; an unmigrated schema fails with a persistence error and is
     * never reported as an empty or a populated table.
     *
     * @param subjectId       identifier of the new subject
     * @param loginIdentifier login identifier and notification address of the new account
     * @param password        initial password; zeroed by this method
     * @return the outcome when this call created the first credential; empty when at least one credential
     *         already existed, in which case nothing is written
     * @throws NullPointerException     if {@code subjectId} is null
     * @throws IllegalArgumentException if the login identifier is null, blank or not an address, or the
     *                                  password is null, empty or outside the {@code PasswordPolicy} window
     * @throws IllegalStateException    if the credential table is subject to row-level security; nothing is
     *                                  written
     * @since 0.1.0
     */
    Optional<ProvisionResult> provisionFirstVerified(UUID subjectId, String loginIdentifier, char[] password);
}
