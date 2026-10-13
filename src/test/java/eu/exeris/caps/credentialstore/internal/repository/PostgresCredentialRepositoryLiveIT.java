package eu.exeris.caps.credentialstore.internal.repository;

import eu.exeris.caps.credentialstore.CredentialStoreModule;
import eu.exeris.caps.credentialstore.api.exception.CredentialAlreadyExistsException;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.credentialstore.internal.CountingPasswordEncoder;
import eu.exeris.caps.credentialstore.internal.DefaultAccountVerification;
import eu.exeris.caps.credentialstore.internal.DefaultCredentialStore;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.spi.InMemoryNotificationDispatcher;
import eu.exeris.kernel.community.persistence.jdbc.JdbcPersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link PostgresCredentialRepository} against a real PostgreSQL, with the schema created from the
 * capability's own migration in a throw-away schema.
 *
 * <p>The connection comes from the environment or system properties, never from a default:
 * {@code EXERIS_TEST_PG_URL} / {@code exeris.test.pg.url} (a JDBC URL), {@code EXERIS_TEST_PG_USER} /
 * {@code exeris.test.pg.user} and {@code EXERIS_TEST_PG_PASSWORD} / {@code exeris.test.pg.password}. Without
 * all three the class is skipped.
 */
@DisplayName("PostgresCredentialRepository on a live PostgreSQL")
class PostgresCredentialRepositoryLiveIT {

    private static final String TEST_SCHEMA = "test_credential_store_live";
    private static final LockoutPolicy POLICY = new LockoutPolicy(5, Duration.ofMinutes(15), Duration.ofMinutes(15));

    private static String url;
    private static String user;
    private static String password;
    private static PostgresCredentialRepository repository;
    private static TransactionalExecutor tx;

    @BeforeAll
    static void setUpDatabase() throws Exception {
        url = setting("EXERIS_TEST_PG_URL", "exeris.test.pg.url");
        user = setting("EXERIS_TEST_PG_USER", "exeris.test.pg.user");
        password = setting("EXERIS_TEST_PG_PASSWORD", "exeris.test.pg.password");
        Assumptions.assumeTrue(url != null && user != null && password != null,
                "set EXERIS_TEST_PG_URL, EXERIS_TEST_PG_USER and EXERIS_TEST_PG_PASSWORD "
                        + "(or the exeris.test.pg.* system properties) to run against PostgreSQL");

        try (Connection conn = DriverManager.getConnection(url, user, password);
             Statement stmt = conn.createStatement()) {
            stmt.execute("DROP SCHEMA IF EXISTS " + TEST_SCHEMA + " CASCADE");
            stmt.execute("CREATE SCHEMA " + TEST_SCHEMA);
        }
        try (Connection conn = open(); Statement stmt = conn.createStatement()) {
            for (String migration : CredentialStoreModule.MIGRATIONS) {
                for (String statement : statements(read(migration))) {
                    stmt.execute(statement);
                }
            }
        }
        tx = new PerCallExecutor();
        repository = new PostgresCredentialRepository(tx);
    }

    @AfterAll
    static void dropSchema() throws SQLException {
        if (url == null || user == null || password == null) {
            return;
        }
        try (Connection conn = DriverManager.getConnection(url, user, password);
             Statement stmt = conn.createStatement()) {
            stmt.execute("DROP SCHEMA IF EXISTS " + TEST_SCHEMA + " CASCADE");
        }
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MICROS);
    }

    private static String login() {
        return "user-" + UUID.randomUUID() + "@exeris.eu";
    }

    private static String randomHash() {
        return (UUID.randomUUID().toString() + UUID.randomUUID()).replace("-", "");
    }

    @Test
    @DisplayName("insert is insert-only for both the subject and the login identifier")
    void insertOnly() {
        UUID subject = UUID.randomUUID();
        String login = login();
        Instant now = now();

        assertThat(repository.insertCredential(subject, login, "$argon2id$original", now)).isTrue();
        assertThat(repository.insertCredential(subject, login(), "$argon2id$intruder", now)).isFalse();
        assertThat(repository.insertCredential(UUID.randomUUID(), login, "$argon2id$intruder", now)).isFalse();

        CredentialRecord credential = repository.findByLoginIdentifier(login).orElseThrow();
        assertThat(credential.subjectId()).isEqualTo(subject);
        assertThat(credential.passwordHash()).isEqualTo("$argon2id$original");
        assertThat(credential.emailVerified()).isFalse();
        assertThat(credential.tokenVersion()).isEqualTo(1L);
        assertThat(repository.findBySubject(subject)).contains(credential);
    }

    @Test
    @DisplayName("reservations stop at maxAttempts, lock, and restart at one once the lockout ends")
    void lockoutLifecycle() {
        UUID subject = UUID.randomUUID();
        Instant now = now();
        repository.insertCredential(subject, login(), "$argon2id$h", now);

        for (int i = 1; i <= POLICY.maxAttempts(); i++) {
            assertThat(repository.reserveAttempt(subject, POLICY, now)).get()
                    .extracting(CredentialRecord::failedLoginAttempts).isEqualTo(i);
        }
        assertThat(repository.reserveAttempt(subject, POLICY, now)).isEmpty();

        Optional<Instant> locked = repository.lockIfExhausted(subject, POLICY, now);
        assertThat(locked).contains(now.plus(POLICY.lockoutDuration()));
        assertThat(repository.lockIfExhausted(subject, POLICY, now)).as("already locked").isEmpty();
        assertThat(repository.reserveAttempt(subject, POLICY, now.plusSeconds(60))).isEmpty();

        Instant after = now.plus(POLICY.lockoutDuration());
        CredentialRecord restarted = repository.reserveAttempt(subject, POLICY, after).orElseThrow();
        assertThat(restarted.failedLoginAttempts()).isEqualTo(1);
        assertThat(restarted.lockedUntil()).isNull();
        assertThat(restarted.failureWindowStartedAt()).isEqualTo(after);

        repository.clearFailures(subject, after);
        CredentialRecord cleared = repository.findBySubject(subject).orElseThrow();
        assertThat(cleared.failedLoginAttempts()).isZero();
        assertThat(cleared.failureWindowStartedAt()).isNull();
    }

    @Test
    @DisplayName("failures older than the window start a new count")
    void failureWindow() {
        UUID subject = UUID.randomUUID();
        Instant now = now();
        repository.insertCredential(subject, login(), "$argon2id$h", now);
        repository.reserveAttempt(subject, POLICY, now);
        repository.reserveAttempt(subject, POLICY, now);

        CredentialRecord later = repository.reserveAttempt(subject, POLICY, now.plus(POLICY.failureWindow())).orElseThrow();

        assertThat(later.failedLoginAttempts()).isEqualTo(1);
    }

    @Test
    @DisplayName("concurrent reservations never exceed maxAttempts")
    void concurrentReservationsAreBounded() throws Exception {
        UUID subject = UUID.randomUUID();
        Instant now = now();
        repository.insertCredential(subject, login(), "$argon2id$h", now);

        List<Optional<CredentialRecord>> results = concurrently(16, () -> repository.reserveAttempt(subject, POLICY, now));

        assertThat(results.stream().filter(Optional::isPresent).count()).isEqualTo(POLICY.maxAttempts());
        assertThat(repository.findBySubject(subject).orElseThrow().failedLoginAttempts()).isEqualTo(POLICY.maxAttempts());
    }

    @Test
    @DisplayName("hash replacement and password change are guarded by the expected hash")
    void guardedPasswordWrites() {
        UUID subject = UUID.randomUUID();
        Instant now = now();
        repository.insertCredential(subject, login(), "$argon2id$v1", now);
        String resetHash = randomHash();
        repository.issueResetToken(UUID.randomUUID(), subject, resetHash, now.plusSeconds(900), now, now.minusSeconds(60));

        assertThat(repository.replacePasswordHash(subject, "$argon2id$stale", "$argon2id$x", now)).isFalse();
        assertThat(repository.replacePasswordHash(subject, "$argon2id$v1", "$argon2id$v1b", now)).isTrue();
        assertThat(repository.findBySubject(subject).orElseThrow().tokenVersion()).isEqualTo(1L);

        assertThat(repository.changePassword(subject, "$argon2id$v1", "$argon2id$v2", now)).isEmpty();
        assertThat(repository.changePassword(subject, "$argon2id$v1b", "$argon2id$v2", now)).isEqualTo(OptionalLong.of(2L));
        assertThat(repository.findResetToken(resetHash).orElseThrow().consumedAt()).as("reset token voided").isNotNull();
    }

    @Test
    @DisplayName("verification tokens: cooldown, supersession, single use under concurrency, expiry, verified state")
    void verificationTokens() throws Exception {
        UUID subject = UUID.randomUUID();
        Instant now = now();
        repository.insertCredential(subject, login(), "$argon2id$h", now);
        String first = randomHash();
        String second = randomHash();

        assertThat(repository.issueVerificationToken(UUID.randomUUID(), subject, first, now.plusSeconds(3600), now, now.minusSeconds(60))).isTrue();
        assertThat(repository.issueVerificationToken(UUID.randomUUID(), subject, randomHash(), now.plusSeconds(3600), now, now.minusSeconds(60)))
                .as("inside the cooldown").isFalse();
        Instant later = now.plusSeconds(120);
        assertThat(repository.issueVerificationToken(UUID.randomUUID(), subject, second, later.plusSeconds(3600), later, later.minusSeconds(60))).isTrue();

        assertThat(repository.consumeVerificationToken(first, later)).as("superseded").isEmpty();
        assertThat(repository.consumeVerificationToken(second, later.plusSeconds(3600))).as("expired").isEmpty();
        assertThat(repository.findBySubject(subject).orElseThrow().emailVerified()).isFalse();

        List<Optional<UUID>> consumed = concurrently(8, () -> repository.consumeVerificationToken(second, later));
        assertThat(consumed.stream().filter(Optional::isPresent).toList()).containsExactly(Optional.of(subject));
        assertThat(repository.findBySubject(subject).orElseThrow().emailVerified()).isTrue();

        Instant muchLater = later.plusSeconds(600);
        assertThat(repository.issueVerificationToken(UUID.randomUUID(), subject, randomHash(), muchLater.plusSeconds(3600), muchLater, muchLater.minusSeconds(60)))
                .as("already verified").isFalse();
        assertThat(repository.issueVerificationToken(UUID.randomUUID(), UUID.randomUUID(), randomHash(), muchLater, muchLater, muchLater))
                .as("unknown subject").isFalse();
    }

    @Test
    @DisplayName("a reset token is consumed in the same transaction that sets the password, once")
    void resetTokens() throws Exception {
        UUID subject = UUID.randomUUID();
        Instant now = now();
        repository.insertCredential(subject, login(), "$argon2id$old", now);
        repository.reserveAttempt(subject, POLICY, now);
        String older = randomHash();
        String token = randomHash();
        repository.issueResetToken(UUID.randomUUID(), subject, older, now.plusSeconds(900), now, now.minusSeconds(60));
        Instant later = now.plusSeconds(120);
        repository.issueResetToken(UUID.randomUUID(), subject, token, later.plusSeconds(900), later, later.minusSeconds(60));

        assertThat(repository.consumeResetToken(older, "$argon2id$x", later)).as("superseded").isEmpty();
        assertThat(repository.consumeResetToken(token, "$argon2id$x", later.plusSeconds(900))).as("expired").isEmpty();
        assertThat(repository.findBySubject(subject).orElseThrow().passwordHash()).isEqualTo("$argon2id$old");

        List<OptionalLong> versions = concurrently(8, () -> repository.consumeResetToken(token, "$argon2id$new", later));
        assertThat(versions.stream().filter(OptionalLong::isPresent).toList()).containsExactly(OptionalLong.of(2L));

        CredentialRecord credential = repository.findBySubject(subject).orElseThrow();
        assertThat(credential.passwordHash()).isEqualTo("$argon2id$new");
        assertThat(credential.tokenVersion()).isEqualTo(2L);
        assertThat(credential.failedLoginAttempts()).isZero();
        assertThat(credential.emailVerified()).isTrue();
        assertThat(repository.findResetToken(token).orElseThrow().consumedAt()).isEqualTo(later);
    }

    @Test
    @DisplayName("through the services: register, refuse a takeover, gate on verification, then sign in")
    void servicesOverPostgres() {
        InMemoryNotificationDispatcher dispatcher = new InMemoryNotificationDispatcher();
        PasswordHashing hashing = new PasswordHashing(new CountingPasswordEncoder(), new KdfConcurrencyThrottler(4));
        DefaultCredentialStore store = new DefaultCredentialStore(repository, hashing, POLICY, null, null, Clock.systemUTC());
        DefaultAccountVerification verification = new DefaultAccountVerification(
                repository, dispatcher, null, TokenPolicy.defaults(), Clock.systemUTC());
        UUID subject = UUID.randomUUID();
        String login = login();
        char[] pw = "SecretPassword123!".toCharArray();

        store.createCredential(subject, login, pw);
        UUID intruder = UUID.randomUUID();
        String upperCased = login.toUpperCase(java.util.Locale.ROOT);
        char[] takeoverPassword = "Takeover123!".toCharArray();
        assertThatThrownBy(() -> store.createCredential(intruder, upperCased, takeoverPassword))
                .isInstanceOf(CredentialAlreadyExistsException.class);
        assertThat(store.authenticate(login, pw).isUnverified()).isTrue();

        verification.issueVerification(login);
        assertThat(verification.verifyAccount(dispatcher.dispatchedNotifications().getFirst().rawToken())).isEqualTo(subject);
        assertThat(store.authenticate(login, pw).subjectId()).isEqualTo(subject);
        assertThat(store.authenticate(login, "Takeover123!".toCharArray()).isInvalid()).isTrue();
    }

    private static <T> List<T> concurrently(int threads, Callable<T> task) throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        List<Future<T>> futures = new ArrayList<>();
        try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return task.call();
                }));
            }
            start.countDown();
            List<T> results = new ArrayList<>();
            for (Future<T> future : futures) {
                results.add(future.get());
            }
            return results;
        }
    }

    private static String setting(String env, String property) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) {
            value = System.getenv(env);
        }
        return value == null || value.isBlank() ? null : value;
    }

    private static Connection open() throws SQLException {
        String separator = url.contains("?") ? "&" : "?";
        return DriverManager.getConnection(url + separator + "currentSchema=" + TEST_SCHEMA, user, password);
    }

    private static String read(String resource) throws IOException {
        try (InputStream in = PostgresCredentialRepositoryLiveIT.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("missing migration " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static List<String> statements(String sql) {
        String withoutComments = sql.replaceAll("(?m)^\\s*--.*$", "");
        List<String> statements = new ArrayList<>();
        for (String candidate : withoutComments.split(";")) {
            if (!candidate.isBlank()) {
                statements.add(candidate.strip());
            }
        }
        return statements;
    }

    /** One JDBC connection per unit of work, so concurrent callers contend in the database, not in the test. */
    private static final class PerCallExecutor implements TransactionalExecutor {

        @Override
        public void execute(TransactionalWork work) {
            executeManaged(work);
        }

        @Override
        public void executeManaged(TransactionalWork work) {
            try (Connection jdbc = open()) {
                PersistenceConnection conn = new JdbcPersistenceConnection(jdbc);
                conn.beginTransaction();
                try {
                    work.run(conn);
                    conn.commit();
                } catch (RuntimeException e) {
                    conn.rollback();
                    throw e;
                }
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
            executeManaged(work);
        }

        @Override
        public <T> T query(Function<PersistenceConnection, T> query) {
            try (Connection jdbc = open()) {
                return query.apply(new JdbcPersistenceConnection(jdbc));
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
