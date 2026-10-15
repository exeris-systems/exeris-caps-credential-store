package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.exception.CredentialAlreadyExistsException;
import eu.exeris.caps.credentialstore.api.model.CredentialVerificationResult;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.api.model.ProvisionResult;
import eu.exeris.caps.credentialstore.internal.audit.AuditTrailBridge;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRecord;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
import eu.exeris.caps.credentialstore.spi.AuditRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DefaultCredentialProvisioning")
class DefaultCredentialProvisioningTest {

    private static final String LOGIN = "operator@exeris.eu";
    private static final char[] PASSWORD = "BootstrapPassword123!".toCharArray();
    private static final PasswordPolicy POLICY = new PasswordPolicy(8, 64);

    private InMemoryCredentialRepository repository;
    private CountingPasswordEncoder encoder;
    private MutableClock clock;
    private List<RecordedEvent> recordedEvents;
    private boolean failingAudit;
    private DefaultCredentialStore store;
    private DefaultCredentialProvisioning provisioning;

    private record RecordedEvent(String action, UUID subjectId, Map<String, Object> details, Instant occurredAt) {}

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        encoder = new CountingPasswordEncoder();
        clock = new MutableClock(Instant.parse("2026-10-15T12:00:00Z"));
        recordedEvents = new ArrayList<>();
        failingAudit = false;

        AuditRecorder recorder = (action, subjectId, details, occurredAt) -> {
            recordedEvents.add(new RecordedEvent(action, subjectId, details, occurredAt));
            if (failingAudit) {
                throw new IllegalStateException("audit downstream unavailable");
            }
        };
        AuditTrailBridge auditBridge = new AuditTrailBridge(recorder, clock);
        PasswordHashing hashing = new PasswordHashing(encoder, new KdfConcurrencyThrottler(4));

        store = new DefaultCredentialStore(
                repository, hashing, LockoutPolicy.defaults(), POLICY, null, auditBridge, clock);
        provisioning = new DefaultCredentialProvisioning(
                repository, hashing, POLICY, auditBridge, clock);
    }

    @Test
    @DisplayName("authenticate returns success right after provisioning")
    void authenticateReturnsSuccessRightAfterProvisioning() {
        UUID subject = UUID.randomUUID();
        char[] pw = PASSWORD.clone();

        ProvisionResult result = provisioning.provisionVerified(subject, "  Operator@Exeris.EU ", pw);

        assertThat(result.subjectId()).isEqualTo(subject);
        assertThat(result.loginIdentifier()).isEqualTo(LOGIN);
        assertThat(result.isSuccess()).isTrue();

        CredentialRecord record = repository.findBySubject(subject).orElseThrow();
        assertThat(record.loginIdentifier()).isEqualTo(LOGIN);
        assertThat(record.emailVerified()).isTrue();
        assertThat(record.verifiedAt()).isEqualTo(clock.instant());
        assertThat(record.passwordHash()).startsWith("$argon2id$");
        assertThat(store.isVerified(subject)).isTrue();

        CredentialVerificationResult auth = store.authenticate(LOGIN, PASSWORD.clone());
        assertThat(auth.isSuccess()).isTrue();
        assertThat(auth.subjectId()).isEqualTo(subject);

        CredentialVerificationResult verified = store.verifyCredential(subject, PASSWORD.clone());
        assertThat(verified.isSuccess()).isTrue();
        assertThat(verified.subjectId()).isEqualTo(subject);
    }

    @Test
    @DisplayName("password shorter than minLength refused")
    void passwordShorterThanMinLengthRefused() {
        UUID subject = UUID.randomUUID();
        char[] shortPw = "short".toCharArray();
        int beforeDerivations = encoder.encodeCount();

        assertThatThrownBy(() -> provisioning.provisionVerified(subject, LOGIN, shortPw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least 8");

        assertThat(encoder.encodeCount()).isEqualTo(beforeDerivations);
        assertThat(repository.findBySubject(subject)).isEmpty();
        assertThat(shortPw).as("password array zeroed on policy refusal").containsOnly('\0');
    }

    @Test
    @DisplayName("password longer than maxLength refused")
    void passwordLongerThanMaxLengthRefused() {
        UUID subject = UUID.randomUUID();
        char[] longPw = "x".repeat(65).toCharArray();
        int beforeDerivations = encoder.encodeCount();

        assertThatThrownBy(() -> provisioning.provisionVerified(subject, LOGIN, longPw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at most 64");

        assertThat(encoder.encodeCount()).isEqualTo(beforeDerivations);
        assertThat(repository.findBySubject(subject)).isEmpty();
        assertThat(longPw).as("password array zeroed on policy refusal").containsOnly('\0');
    }

    @Test
    @DisplayName("duplicate identifier refused")
    void duplicateIdentifierRefused() {
        UUID firstSubject = UUID.randomUUID();
        provisioning.provisionVerified(firstSubject, LOGIN, PASSWORD.clone());
        String originalHash = repository.findBySubject(firstSubject).orElseThrow().passwordHash();

        UUID intruderSubject = UUID.randomUUID();
        char[] intruderPw = "AttackerPassword123!".toCharArray();

        assertThatThrownBy(() -> provisioning.provisionVerified(intruderSubject, "OPERATOR@exeris.eu", intruderPw))
                .isInstanceOf(CredentialAlreadyExistsException.class)
                .hasMessageNotContaining(LOGIN);

        assertThat(repository.findBySubject(intruderSubject)).isEmpty();
        assertThat(repository.findBySubject(firstSubject).orElseThrow().passwordHash()).isEqualTo(originalHash);
        assertThat(intruderPw).as("password array zeroed on duplicate refusal").containsOnly('\0');

        char[] anotherPw = "AnotherPassword123!".toCharArray();
        assertThatThrownBy(() -> provisioning.provisionVerified(firstSubject, "other@exeris.eu", anotherPw))
                .isInstanceOf(CredentialAlreadyExistsException.class)
                .hasMessageNotContaining(firstSubject.toString());
        assertThat(anotherPw).as("password array zeroed on duplicate refusal").containsOnly('\0');
    }

    @Test
    @DisplayName("refuses overwrite of existing unverified credential")
    void refusesOverwriteOfExistingUnverifiedCredential() {
        UUID existingSubject = UUID.randomUUID();
        store.createCredential(existingSubject, "unverified@exeris.eu", "OriginalPassword123!".toCharArray());

        char[] pw = PASSWORD.clone();
        assertThatThrownBy(() -> provisioning.provisionVerified(existingSubject, "different@exeris.eu", pw))
                .isInstanceOf(CredentialAlreadyExistsException.class);

        char[] pw2 = PASSWORD.clone();
        assertThatThrownBy(() -> provisioning.provisionVerified(UUID.randomUUID(), "unverified@exeris.eu", pw2))
                .isInstanceOf(CredentialAlreadyExistsException.class);
    }

    @Test
    @DisplayName("audit event emitted with the provisioning type")
    void auditEventEmittedWithProvisioningType() {
        UUID subject = UUID.randomUUID();

        provisioning.provisionVerified(subject, LOGIN, PASSWORD.clone());

        assertThat(recordedEvents).hasSize(1);
        RecordedEvent event = recordedEvents.getFirst();
        assertThat(event.action()).isEqualTo("CREDENTIAL_PROVISIONED");
        assertThat(event.subjectId()).isEqualTo(subject);
        assertThat(event.occurredAt()).isEqualTo(clock.instant());
        assertThat(event.details()).isEmpty();
    }

    @Test
    @DisplayName("a failing audit recorder does not fail provisioning")
    void failingAuditRecorderDoesNotFailProvisioning() {
        failingAudit = true;
        UUID subject = UUID.randomUUID();

        ProvisionResult result = provisioning.provisionVerified(subject, LOGIN, PASSWORD.clone());

        assertThat(result.subjectId()).isEqualTo(subject);
        assertThat(repository.findBySubject(subject)).isPresent();
        assertThat(store.authenticate(LOGIN, PASSWORD.clone()).isSuccess()).isTrue();
    }

    @Test
    @DisplayName("password array zeroed on success")
    void passwordArrayZeroedOnSuccess() {
        UUID subject = UUID.randomUUID();
        char[] pw = PASSWORD.clone();

        provisioning.provisionVerified(subject, LOGIN, pw);

        assertThat(pw).containsOnly('\0');
    }

    @Test
    @DisplayName("rejects malformed arguments before anything is written")
    void rejectsMalformedArguments() {
        UUID subject = UUID.randomUUID();
        char[] pw = PASSWORD.clone();

        assertThatThrownBy(() -> provisioning.provisionVerified(null, LOGIN, pw))
                .isInstanceOf(NullPointerException.class);
        assertThat(pw).as("password array zeroed on null subject").containsOnly('\0');

        char[] pw2 = PASSWORD.clone();
        assertThatThrownBy(() -> provisioning.provisionVerified(subject, "   ", pw2))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(pw2).as("password array zeroed on blank login").containsOnly('\0');

        char[] pw3 = PASSWORD.clone();
        assertThatThrownBy(() -> provisioning.provisionVerified(subject, "no-at-sign", pw3))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(pw3).as("password array zeroed on invalid address").containsOnly('\0');

        assertThatThrownBy(() -> provisioning.provisionVerified(subject, LOGIN, null))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> provisioning.provisionVerified(subject, LOGIN, new char[0]))
                .isInstanceOf(IllegalArgumentException.class);

        assertThat(repository.findBySubject(subject)).isEmpty();
    }
}
