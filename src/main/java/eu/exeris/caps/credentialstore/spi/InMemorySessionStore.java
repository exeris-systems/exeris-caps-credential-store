package eu.exeris.caps.credentialstore.spi;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe in-memory test double and standalone default for {@link SessionStore}.
 *
 * @since 0.1.0
 */
public final class InMemorySessionStore implements SessionStore {

    private final List<UUID> revokedSubjects = new CopyOnWriteArrayList<>();

    @Override
    public void revokeAllForSubject(UUID subjectId) {
        revokedSubjects.add(subjectId);
    }

    public List<UUID> revokedSubjects() {
        return List.copyOf(revokedSubjects);
    }

    public void clear() {
        revokedSubjects.clear();
    }
}
