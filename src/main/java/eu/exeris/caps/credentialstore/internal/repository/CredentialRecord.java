package eu.exeris.caps.credentialstore.internal.repository;

import java.time.Instant;
import java.util.UUID;

/**
 * One row of {@code credential_records}.
 */
public record CredentialRecord(
        UUID subjectId,
        String loginIdentifier,
        String passwordHash,
        boolean emailVerified,
        Instant verifiedAt,
        int failedLoginAttempts,
        Instant failureWindowStartedAt,
        Instant lockedUntil,
        long tokenVersion,
        Instant createdAt,
        Instant updatedAt
) {
}
