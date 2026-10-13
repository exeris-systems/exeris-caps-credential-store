package eu.exeris.caps.credentialstore.spi;

import java.util.UUID;

/**
 * Capability SPI contract for active session invalidation (ADR-099 Obligation 9).
 *
 * @since 0.1.0
 */
public interface SessionStore {

    /**
     * Revokes all active sessions for the specified subject identifier.
     *
     * @param subjectId identity subject identifier
     */
    void revokeAllForSubject(UUID subjectId);
}
