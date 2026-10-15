package eu.exeris.caps.credentialstore.api.model;

import java.util.Objects;
import java.util.UUID;

/**
 * Outcome of provisioning a verified credential for an account.
 *
 * @param subjectId       identifier of the provisioned subject
 * @param loginIdentifier normalised login identifier of the provisioned account
 * @since 0.1.0
 */
public record ProvisionResult(UUID subjectId, String loginIdentifier) {

    public ProvisionResult {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(loginIdentifier, "loginIdentifier must not be null");
    }

    /**
     * Creates a successful result for the given subject and normalised login identifier.
     *
     * @param subjectId       provisioned subject identifier; required
     * @param loginIdentifier normalised login identifier; required
     * @return the result
     */
    public static ProvisionResult success(UUID subjectId, String loginIdentifier) {
        return new ProvisionResult(subjectId, loginIdentifier);
    }

    /**
     * Reports whether the provisioning succeeded.
     *
     * @return {@code true}
     */
    public boolean isSuccess() {
        return true;
    }
}
