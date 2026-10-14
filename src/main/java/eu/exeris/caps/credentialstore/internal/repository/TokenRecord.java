package eu.exeris.caps.credentialstore.internal.repository;

import java.time.Instant;
import java.util.UUID;

/**
 * One row of a token table. {@code consumedAt} is the time the token stopped being usable, whether it was
 * consumed or superseded by a newer token.
 */
public record TokenRecord(
        UUID id,
        UUID subjectId,
        String tokenHash,
        Instant expiresAt,
        Instant createdAt,
        Instant consumedAt
) {

    /**
     * Tells whether the token can still be redeemed at the given instant.
     *
     * @param now the current time
     * @return {@code true} if the token is neither consumed, superseded nor expired at {@code now}
     */
    public boolean usableAt(Instant now) {
        return consumedAt == null && expiresAt.isAfter(now);
    }
}
