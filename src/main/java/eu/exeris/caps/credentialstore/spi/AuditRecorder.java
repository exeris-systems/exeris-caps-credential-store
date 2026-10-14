package eu.exeris.caps.credentialstore.spi;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Receiver of the security events this capability records (credential created, sign-in failed, account
 * locked, password changed and so on).
 *
 * <p>The capability emits an event after the state change it describes has committed, and treats a failing
 * recorder as a lost event, not as a failed operation: an exception thrown here is logged and swallowed. The
 * interface names no type of the audit-trail capability, so a composition without that jar loads this
 * capability unchanged; {@link AuditLogSinkRecorder} adapts an audit-trail sink for a composition that has it.
 *
 * @since 0.1.0
 */
@FunctionalInterface
public interface AuditRecorder {

    /**
     * Records one event.
     *
     * @param action     event name, for example {@code PASSWORD_CHANGED}
     * @param subjectId  the affected subject
     * @param details    event metadata; never contains a password, a hash or a token
     * @param occurredAt the instant of the event, read from the capability's clock
     */
    void recordEvent(String action, UUID subjectId, Map<String, Object> details, Instant occurredAt);
}
