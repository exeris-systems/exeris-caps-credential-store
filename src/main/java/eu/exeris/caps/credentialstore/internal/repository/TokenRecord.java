package eu.exeris.caps.credentialstore.internal.repository;

import java.time.Instant;
import java.util.UUID;

/**
 * Internal entity mapping for verification and reset token tables.
 */
public record TokenRecord(
        UUID id,
        UUID subjectId,
        String tokenHash,
        Instant expiresAt,
        Instant createdAt,
        Instant consumedAt
) {
}
