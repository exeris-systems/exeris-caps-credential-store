package eu.exeris.caps.credentialstore.spi;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Adapter from {@link AuditRecorder} to the audit-trail capability's {@link AuditLogSink}.
 *
 * <p>This is the only class of the capability that names an audit-trail type. A composition that carries the
 * audit-trail capability constructs it; a composition without that jar never loads it, and the rest of the
 * capability loads and runs without the jar.
 *
 * @since 0.1.0
 */
public final class AuditLogSinkRecorder implements AuditRecorder {

    private final AuditLogSink sink;

    /**
     * Creates a recorder that forwards every event to the given audit-trail sink.
     *
     * @param sink the audit-trail sink to forward to; required
     */
    public AuditLogSinkRecorder(AuditLogSink sink) {
        this.sink = Objects.requireNonNull(sink, "sink must not be null");
    }

    @Override
    public void recordEvent(String action, UUID subjectId, Map<String, Object> details, Instant occurredAt) {
        sink.emit(AuditEvent.builder()
                .action(action)
                .resourceType("credential")
                .resourceId(subjectId != null ? subjectId.toString() : "")
                .actorId(subjectId != null ? subjectId.toString() : "system")
                .timestamp(occurredAt)
                .details(details)
                .build());
    }
}
