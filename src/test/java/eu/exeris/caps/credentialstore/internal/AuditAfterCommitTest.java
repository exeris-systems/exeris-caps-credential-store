package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.credentialstore.internal.audit.AuditTrailBridge;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
import eu.exeris.caps.credentialstore.spi.AuditRecorder;
import eu.exeris.caps.credentialstore.spi.InMemoryNotificationDispatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("A failing audit recorder never turns a committed success into a failure")
class AuditAfterCommitTest {

    private static final String LOGIN = "user@exeris.eu";
    private static final char[] PASSWORD = "SecretPassword123!".toCharArray();
    private static final char[] NEXT = "NextPassword456!".toCharArray();

    private final List<Instant> recordedAt = new ArrayList<>();
    private boolean failing = true;
    private InMemoryCredentialRepository repository;
    private InMemoryNotificationDispatcher dispatcher;
    private MutableClock clock;
    private DefaultCredentialStore store;
    private DefaultAccountVerification verification;
    private DefaultCredentialRecovery recovery;
    private DefaultCredentialProvisioning provisioning;

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        dispatcher = new InMemoryNotificationDispatcher();
        clock = new MutableClock(Instant.parse("2026-10-13T12:00:00Z"));
        AuditRecorder recorder = (action, subject, details, at) -> {
            recordedAt.add(at);
            if (failing) {
                throw new IllegalStateException("audit sink down");
            }
        };
        AuditTrailBridge audit = new AuditTrailBridge(recorder, clock);
        PasswordHashing hashing = new PasswordHashing(new CountingPasswordEncoder(), new KdfConcurrencyThrottler(2));
        TokenPolicy tokens = TokenPolicy.defaults();
        store = new DefaultCredentialStore(repository, hashing, LockoutPolicy.defaults(), PasswordPolicy.defaults(), null, audit, clock);
        verification = new DefaultAccountVerification(repository, dispatcher, audit, tokens, clock);
        recovery = new DefaultCredentialRecovery(repository, hashing, dispatcher, null, audit, tokens, PasswordPolicy.defaults(), clock);
        provisioning = new DefaultCredentialProvisioning(repository, hashing, PasswordPolicy.defaults(), audit, clock);
    }

    @Test
    @DisplayName("create, verify, sign in, change and reset all complete and keep their effects")
    void everyOperationCompletes() {
        UUID subject = UUID.randomUUID();
        store.createCredential(subject, LOGIN, PASSWORD);
        verification.issueVerification(LOGIN);
        assertThat(verification.verifyAccount(dispatcher.dispatchedNotifications().getLast().rawToken()))
                .isEqualTo(subject);
        assertThat(store.authenticate(LOGIN, PASSWORD).isSuccess()).isTrue();

        store.changePassword(subject, PASSWORD, NEXT);
        assertThat(store.authenticate(LOGIN, NEXT).isSuccess()).isTrue();

        clock.advance(java.time.Duration.ofMinutes(5));
        recovery.requestReset(LOGIN);
        recovery.consumeReset(dispatcher.dispatchedNotifications().getLast().rawToken(), PASSWORD);
        assertThat(store.authenticate(LOGIN, PASSWORD).isSuccess()).isTrue();
        assertThat(store.getTokenVersion(subject)).hasValue(3);

        UUID bootstrapSubject = UUID.randomUUID();
        char[] bootstrapPassword = "BootstrapPassword123!".toCharArray();
        provisioning.provisionVerified(bootstrapSubject, "bootstrap@exeris.eu", bootstrapPassword);
        assertThat(store.authenticate("bootstrap@exeris.eu", "BootstrapPassword123!".toCharArray()).isSuccess()).isTrue();
    }

    @Test
    @DisplayName("events carry the injected clock's instant")
    void eventsUseTheInjectedClock() {
        failing = false;
        store.createCredential(UUID.randomUUID(), LOGIN, PASSWORD);
        char[] bootstrapPassword = "BootstrapPassword123!".toCharArray();
        provisioning.provisionVerified(UUID.randomUUID(), "bootstrap@exeris.eu", bootstrapPassword);

        assertThat(recordedAt).containsExactly(clock.instant(), clock.instant());
    }
}
