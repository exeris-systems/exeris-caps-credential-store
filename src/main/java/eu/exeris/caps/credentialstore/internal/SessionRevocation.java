package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.spi.SessionStore;

import java.util.UUID;

/**
 * Orders session revocation around a password write so that the write cannot succeed while the sessions it is
 * meant to evict stay alive.
 *
 * <p>The session store runs in a unit of work of its own and cannot join the credential transaction, so no
 * single commit covers both. The order is therefore:
 * <ol>
 *   <li>{@link #beforeWrite} revokes every session of the subject <em>before</em> the password is written. If
 *       it throws, nothing has been written: the password, the token version and a reset token are as they
 *       were, and the caller may retry. A password write is never reached with revocation skipped.</li>
 *   <li>The write commits.</li>
 *   <li>{@link #afterWrite} revokes again, to evict a session that was opened with the old password between
 *       step 1 and the commit. Its failure cannot undo the write, so it is logged, not thrown; the token
 *       version the write incremented is what a verifier compares against for that residual window.</li>
 * </ol>
 */
final class SessionRevocation {

    private static final System.Logger LOG = System.getLogger(SessionRevocation.class.getName());

    private final SessionStore sessionStore;

    SessionRevocation(SessionStore sessionStore) {
        this.sessionStore = sessionStore;
    }

    /** Revokes every session of the subject; a failure propagates and aborts the password write. */
    void beforeWrite(UUID subjectId) {
        if (sessionStore != null) {
            sessionStore.revokeAllForSubject(subjectId);
        }
    }

    /** Second sweep after the commit; never throws. */
    void afterWrite(UUID subjectId) {
        if (sessionStore == null) {
            return;
        }
        try {
            sessionStore.revokeAllForSubject(subjectId);
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.ERROR,
                    "post-commit session sweep failed for a subject whose password changed; sessions opened "
                            + "during the change are not revoked, the incremented token version still refuses "
                            + "their tokens: " + e.getClass().getName());
        }
    }
}
