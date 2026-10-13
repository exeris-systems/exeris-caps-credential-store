package eu.exeris.caps.credentialstore.internal.audit;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Bridge for emitting compliance events to {@link AuditLogSink} when present.
 *
 * @since 0.1.0
 */
public final class AuditTrailBridge {

    private final AuditLogSink sink;

    public AuditTrailBridge(AuditLogSink sink) {
        this.sink = sink;
    }

    /**
     * Emits an audit event if the underlying sink is configured.
     *
     * @param action audit action name
     * @param subjectId affected subject identifier
     * @param details event metadata
     */
    public void emit(String action, UUID subjectId, Map<String, Object> details) {
        if (sink != null) {
            sink.emit(AuditEvent.builder()
                    .action(action)
                    .resourceType("credential")
                    .resourceId(subjectId != null ? subjectId.toString() : "")
                    .actorId(subjectId != null ? subjectId.toString() : "system")
                    .timestamp(Instant.now())
                    .details(details)
                    .build());
        }
    }
}
