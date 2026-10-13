package eu.exeris.caps.credentialstore.api;

/**
 * Extension contract for password encoders that support transparent migration
 * and parameter upgrading per ADR-099.
 *
 * <p>Implemented by encoders that can detect whether a stored hash string is legacy
 * or needs re-hashing to a modern algorithm (e.g. BCrypt to Argon2id).
 *
 * @since 0.1.0
 */
public interface RehashablePasswordEncoder {

    /**
     * Checks if the given encoded hash string requires upgrading to a modern algorithm.
     *
     * @param encoded the existing password hash stored in the database
     * @return {@code true} if the hash should be transparently upgraded upon successful authentication
     */
    boolean needsRehash(String encoded);
}
