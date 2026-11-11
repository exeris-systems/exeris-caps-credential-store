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
import eu.exeris.caps.credentialstore.internal.repository.CredentialRepository;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
import eu.exeris.caps.credentialstore.spi.AuditRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behaviour of {@code provisionFirstVerified} against the in-memory repository: outcomes, refusals, zeroing,
 * audit and disclosure. Atomicity against concurrent writers is covered on a live PostgreSQL.
 */
@DisplayName("DefaultCredentialProvisioning.provisionFirstVerified")
class DefaultCredentialProvisioningFirstTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final PasswordPolicy POLICY = new PasswordPolicy(8, 64);

    private InMemoryCredentialRepository repository;
    private CountingPasswordEncoder encoder;
    private MutableClock clock;
    private List<Recorded> events;
    private boolean failingAudit;
    private boolean subjectPresentWhenAudited;
    private DefaultCredentialStore store;
    private DefaultCredentialProvisioning provisioning;
    private AtomicInteger firstInserts;

    private record Recorded(String action, UUID subjectId, Map<String, Object> details) {}

    private static char[] newPassword() {
        char[] pw = new char[24];
        for (int i = 0; i < pw.length; i++) {
            pw[i] = ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length()));
        }
        return pw;
    }

    private static String newLogin() {
        return "user-" + UUID.randomUUID() + "@exeris.eu";
    }

    @BeforeEach
    void setUp() {
        repository = new InMemoryCredentialRepository();
        encoder = new CountingPasswordEncoder();
        clock = new MutableClock(Instant.parse("2026-10-15T12:00:00Z"));
        events = new ArrayList<>();
        failingAudit = false;
        subjectPresentWhenAudited = false;
        firstInserts = new AtomicInteger();
        AuditRecorder recorder = (action, subjectId, details, occurredAt) -> {
            events.add(new Recorded(action, subjectId, details));
            subjectPresentWhenAudited = repository.findBySubject(subjectId).isPresent();
            if (failingAudit) {
                throw new IllegalStateException("audit downstream unavailable");
            }
        };
        AuditTrailBridge audit = new AuditTrailBridge(recorder, clock);
        PasswordHashing hashing = new PasswordHashing(encoder, new KdfConcurrencyThrottler(4));
        store = new DefaultCredentialStore(repository, hashing, LockoutPolicy.defaults(), POLICY, null, audit, clock);
        provisioning = new DefaultCredentialProvisioning(countingRepository(repository), hashing, POLICY, audit, clock);
    }

    /** Wraps the repository so that calls to the first-credential insert can be counted. */
    private CredentialRepository countingRepository(CredentialRepository delegate) {
        return (CredentialRepository) Proxy.newProxyInstance(CredentialRepository.class.getClassLoader(),
                new Class<?>[] {CredentialRepository.class}, (proxy, method, args) -> {
                    if (method.getName().equals("insertFirstVerifiedCredential")) {
                        firstInserts.incrementAndGet();
                    }
                    try {
                        return method.invoke(delegate, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
    }

    @Test
    @DisplayName("an empty table yields the result with the subject and the normalised login, and one credential")
    void emptyTableCreatesTheFirstCredential() {
        UUID subject = UUID.randomUUID();
        String login = newLogin();

        Optional<ProvisionResult> result = provisioning.provisionFirstVerified(
                subject, "  " + login.toUpperCase(java.util.Locale.ROOT) + " ", newPassword());

        assertThat(result).isPresent();
        assertThat(result.get().subjectId()).isEqualTo(subject);
        assertThat(result.get().loginIdentifier()).isEqualTo(login);
        assertThat(result.get().isSuccess()).isTrue();
        CredentialRecord record = repository.findBySubject(subject).orElseThrow();
        assertThat(record.loginIdentifier()).isEqualTo(login);
        assertThat(record.passwordHash()).startsWith("$argon2id$");
        assertThat(repository.findByLoginIdentifier(login)).isPresent();
    }

    @Test
    @DisplayName("the credential is verified at once: authenticate succeeds and no verification token exists")
    void createdCredentialIsVerified() {
        UUID subject = UUID.randomUUID();
        String login = newLogin();
        char[] pw = newPassword();
        char[] sameAgain = pw.clone();

        provisioning.provisionFirstVerified(subject, login, pw);

        CredentialRecord record = repository.findBySubject(subject).orElseThrow();
        assertThat(record.emailVerified()).isTrue();
        assertThat(record.verifiedAt()).isEqualTo(clock.instant());
        assertThat(repository.verificationTokens()).isEmpty();
        assertThat(repository.resetTokens()).isEmpty();
        CredentialVerificationResult auth = store.authenticate(login, sameAgain);
        assertThat(auth.isSuccess()).isTrue();
        assertThat(auth.isUnverified()).isFalse();
        assertThat(auth.subjectId()).isEqualTo(subject);
    }

    @Test
    @DisplayName("an existing unverified credential refuses: empty, nothing changed, no audit event")
    void existingUnverifiedCredentialRefuses() {
        UUID existing = UUID.randomUUID();
        String existingLogin = newLogin();
        store.createCredential(existing, existingLogin, newPassword());
        CredentialRecord before = repository.findBySubject(existing).orElseThrow();
        events.clear();
        int encodes = encoder.encodeCount();
        UUID candidate = UUID.randomUUID();
        char[] pw = newPassword();

        Optional<ProvisionResult> result = provisioning.provisionFirstVerified(candidate, newLogin(), pw);

        assertThat(result).isEmpty();
        assertThat(repository.findBySubject(candidate)).isEmpty();
        assertThat(repository.findBySubject(existing)).contains(before);
        assertThat(events).as("a refused attempt is not audited").isEmpty();
        assertThat(encoder.encodeCount()).as("only the candidate's own derivation ran").isEqualTo(encodes + 1);
        assertThat(pw).containsOnly('\0');
    }

    @Test
    @DisplayName("an existing verified credential refuses and leaves its hash unchanged")
    void existingVerifiedCredentialRefuses() {
        UUID existing = UUID.randomUUID();
        provisioning.provisionFirstVerified(existing, newLogin(), newPassword());
        CredentialRecord before = repository.findBySubject(existing).orElseThrow();
        events.clear();

        Optional<ProvisionResult> result =
                provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), newPassword());

        assertThat(result).isEmpty();
        assertThat(repository.findBySubject(existing)).contains(before);
        assertThat(events).isEmpty();
    }

    @Test
    @DisplayName("an existing credential with the same subject or the same login still yields empty, never an exception")
    void sameSubjectOrLoginYieldsEmpty() {
        UUID existing = UUID.randomUUID();
        String existingLogin = newLogin();
        store.createCredential(existing, existingLogin, newPassword());
        CredentialRecord before = repository.findBySubject(existing).orElseThrow();

        assertThat(provisioning.provisionFirstVerified(existing, newLogin(), newPassword())).isEmpty();
        assertThat(provisioning.provisionFirstVerified(UUID.randomUUID(), existingLogin.toUpperCase(java.util.Locale.ROOT),
                newPassword())).isEmpty();
        assertThat(provisioning.provisionFirstVerified(existing, existingLogin, newPassword())).isEmpty();

        assertThat(repository.findBySubject(existing)).contains(before);
    }

    @Test
    @DisplayName("provisionVerified keeps refusing a duplicate with an exception")
    void provisionVerifiedUnchanged() {
        UUID existing = UUID.randomUUID();
        String login = newLogin();
        provisioning.provisionVerified(existing, login, newPassword());
        char[] pw = newPassword();

        assertThatThrownBy(() -> provisioning.provisionVerified(UUID.randomUUID(), login, pw))
                .isInstanceOf(CredentialAlreadyExistsException.class);
        assertThat(pw).containsOnly('\0');
    }

    @Test
    @DisplayName("a second call after a first success yields empty")
    void secondCallYieldsEmpty() {
        assertThat(provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), newPassword())).isPresent();
        assertThat(provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), newPassword())).isEmpty();
    }

    @Test
    @DisplayName("refusals match provisionVerified, touch nothing and run no derivation")
    void inputRefusals() {
        UUID subject = UUID.randomUUID();
        int encodes = encoder.encodeCount();

        char[] pw = newPassword();
        assertThatThrownBy(() -> provisioning.provisionFirstVerified(null, newLogin(), pw))
                .isInstanceOf(NullPointerException.class);
        assertThat(pw).as("null subject").containsOnly('\0');

        for (String badLogin : new String[] {null, "", "   ", "no-at-sign"}) {
            char[] p = newPassword();
            assertThatThrownBy(() -> provisioning.provisionFirstVerified(subject, badLogin, p))
                    .as("login %s", badLogin).isInstanceOf(IllegalArgumentException.class);
            assertThat(p).as("array zeroed for login %s", badLogin).containsOnly('\0');
        }

        assertThatThrownBy(() -> provisioning.provisionFirstVerified(subject, newLogin(), null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> provisioning.provisionFirstVerified(subject, newLogin(), new char[0]))
                .isInstanceOf(IllegalArgumentException.class);
        char[] tooShort = "short".toCharArray();
        assertThatThrownBy(() -> provisioning.provisionFirstVerified(subject, newLogin(), tooShort))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(tooShort).containsOnly('\0');
        char[] tooLong = "x".repeat(65).toCharArray();
        assertThatThrownBy(() -> provisioning.provisionFirstVerified(subject, newLogin(), tooLong))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(tooLong).containsOnly('\0');

        assertThat(firstInserts.get()).as("repository never reached").isZero();
        assertThat(encoder.encodeCount()).as("no derivation ran").isEqualTo(encodes);
        assertThat(repository.findBySubject(subject)).isEmpty();
        assertThat(events).isEmpty();
    }

    @Test
    @DisplayName("the same refusal messages as provisionVerified")
    void refusalMessagesMatch() {
        UUID subject = UUID.randomUUID();
        String login = newLogin();
        String viaVerified = messageOf(() -> provisioning.provisionVerified(subject, login, "short".toCharArray()));
        String viaFirst = messageOf(() -> provisioning.provisionFirstVerified(subject, login, "short".toCharArray()));
        assertThat(viaFirst).isEqualTo(viaVerified);
        assertThat(messageOf(() -> provisioning.provisionFirstVerified(subject, "no-at-sign", newPassword())))
                .isEqualTo(messageOf(() -> provisioning.provisionVerified(subject, "no-at-sign", newPassword())));
        assertThat(messageOf(() -> provisioning.provisionFirstVerified(null, login, newPassword())))
                .isEqualTo(messageOf(() -> provisioning.provisionVerified(null, login, newPassword())));
    }

    private static String messageOf(Runnable action) {
        try {
            action.run();
        } catch (RuntimeException e) {
            return e.getClass().getName() + ": " + e.getMessage();
        }
        throw new AssertionError("expected a refusal");
    }

    @Test
    @DisplayName("the array is zeroed on success, on empty and when the repository fails")
    void arrayZeroedOnEveryPath() {
        char[] success = newPassword();
        provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), success);
        assertThat(success).as("success").containsOnly('\0');

        char[] refused = newPassword();
        assertThat(provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), refused)).isEmpty();
        assertThat(refused).as("empty").containsOnly('\0');

        for (RuntimeException failure : new RuntimeException[] {
                new IllegalStateException("simulated row-level security refusal"),
                new IllegalArgumentException("simulated"),
                new UnsupportedOperationException("simulated database failure")}) {
            DefaultCredentialProvisioning failing = new DefaultCredentialProvisioning(failingRepository(failure),
                    new PasswordHashing(encoder, new KdfConcurrencyThrottler(4)), POLICY, null, clock);
            char[] pw = newPassword();
            assertThatThrownBy(() -> failing.provisionFirstVerified(UUID.randomUUID(), newLogin(), pw)).isSameAs(failure);
            assertThat(pw).as("repository failure %s", failure.getClass().getSimpleName()).containsOnly('\0');
        }
    }

    private static CredentialRepository failingRepository(RuntimeException failure) {
        return (CredentialRepository) Proxy.newProxyInstance(CredentialRepository.class.getClassLoader(),
                new Class<?>[] {CredentialRepository.class}, (proxy, method, args) -> {
                    throw failure;
                });
    }

    @Test
    @DisplayName("one CREDENTIAL_PROVISIONED event for the subject, empty details, recorded after the insert")
    void auditOnSuccess() {
        UUID subject = UUID.randomUUID();

        provisioning.provisionFirstVerified(subject, newLogin(), newPassword());

        assertThat(events).hasSize(1);
        assertThat(events.getFirst().action()).isEqualTo("CREDENTIAL_PROVISIONED");
        assertThat(events.getFirst().subjectId()).isEqualTo(subject);
        assertThat(events.getFirst().details()).isEmpty();
        assertThat(subjectPresentWhenAudited).as("credential existed when the event was emitted").isTrue();
    }

    @Test
    @DisplayName("a failing audit recorder does not turn a success into a failure")
    void failingAuditDoesNotFail() {
        failingAudit = true;
        UUID subject = UUID.randomUUID();
        String login = newLogin();
        char[] pw = newPassword();
        char[] again = pw.clone();

        Optional<ProvisionResult> result = provisioning.provisionFirstVerified(subject, login, pw);

        assertThat(result).isPresent();
        assertThat(repository.findBySubject(subject)).isPresent();
        assertThat(store.authenticate(login, again).isSuccess()).isTrue();
    }

    @Test
    @DisplayName("results and exceptions disclose neither the password, the hash nor an existing login")
    void noDisclosure() {
        String existingLogin = newLogin();
        UUID existing = UUID.randomUUID();
        char[] existingPw = newPassword();
        String existingPwText = new String(existingPw);
        store.createCredential(existing, existingLogin, existingPw);
        String existingHash = repository.findBySubject(existing).orElseThrow().passwordHash();

        char[] pw = newPassword();
        String pwText = new String(pw);
        Optional<ProvisionResult> refused = provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), pw);

        assertThat(refused).isEmpty();
        assertThat(events).extracting(Recorded::action).doesNotContain("CREDENTIAL_PROVISIONED");

        String badLogin = "not-an-address-" + UUID.randomUUID();
        char[] pw2 = newPassword();
        String pw2Text = new String(pw2);
        assertThatThrownBy(() -> provisioning.provisionFirstVerified(UUID.randomUUID(), badLogin, pw2))
                .satisfies(e -> {
                    assertThat(String.valueOf(e.getMessage())).doesNotContain(badLogin, pw2Text, existingLogin,
                            existingPwText, existingHash);
                });
        String shortPw = "short" + RANDOM.nextInt(10);
        assertThatThrownBy(() -> provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), shortPw.toCharArray()))
                .satisfies(e -> assertThat(String.valueOf(e.getMessage())).doesNotContain(shortPw, existingLogin));
        assertThat(pwText).isNotEmpty();
    }
}
