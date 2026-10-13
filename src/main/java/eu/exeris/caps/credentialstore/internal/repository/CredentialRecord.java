package eu.exeris.caps.credentialstore.internal.repository;

import java.time.Instant;
import java.util.UUID;

/**
 * Internal entity mapping for {@code credential_records}.
 */
public record CredentialRecord(
        UUID subjectId,
        String passwordHash,
        boolean emailVerified,
        Instant verifiedAt,
        int failedLoginAttempts,
        Instant lockedUntil,
        long tokenVersion,
        Instant createdAt,
        Instant updatedAt
) {
}
