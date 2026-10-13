package eu.exeris.caps.credentialstore.spi;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe in-memory test double and standalone default for {@link NotificationDispatcher}.
 *
 * @since 0.1.0
 */
public final class InMemoryNotificationDispatcher implements NotificationDispatcher {

    public record DispatchedNotification(String type, UUID subjectId, String recipientEmail, String rawToken) {}

    private final List<DispatchedNotification> dispatched = new CopyOnWriteArrayList<>();

    @Override
    public void sendVerificationToken(UUID subjectId, String recipientEmail, String rawToken) {
        dispatched.add(new DispatchedNotification("VERIFICATION", subjectId, recipientEmail, rawToken));
    }

    @Override
    public void sendPasswordResetToken(UUID subjectId, String recipientEmail, String rawToken) {
        dispatched.add(new DispatchedNotification("PASSWORD_RESET", subjectId, recipientEmail, rawToken));
    }

    public List<DispatchedNotification> dispatchedNotifications() {
        return List.copyOf(dispatched);
    }

    public void clear() {
        dispatched.clear();
    }
}
