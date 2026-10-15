package eu.exeris.caps.credentialstore.internal.audit;

import eu.exeris.caps.credentialstore.spi.AuditRecorder;

import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Emits security events to an {@link AuditRecorder} after the state change they describe has committed.
 *
 * <p>A recorder that throws loses that event and nothing else: the exception is logged and does not reach
 * the caller, because the operation it reports has already happened and cannot be undone by failing the call.
 *
 * @since 0.1.0
 */
public final class AuditTrailBridge {

    private static final System.Logger LOG = System.getLogger(AuditTrailBridge.class.getName());

    private final AuditRecorder recorder;
    private final Clock clock;

    public AuditTrailBridge(AuditRecorder recorder, Clock clock) {
        this.recorder = Objects.requireNonNull(recorder, "recorder must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    /**
     * Emits an event; never throws.
     *
     * @param action    audit action name
     * @param subjectId affected subject identifier
     * @param details   event metadata
     */
    public void emit(String action, UUID subjectId, Map<String, Object> details) {
        try {
            recorder.recordEvent(action, subjectId, details, clock.instant());
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.WARNING,
                    "audit event " + action + " was not recorded: " + e.getClass().getName());
        }
    }
}
