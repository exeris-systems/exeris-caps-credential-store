package eu.exeris.caps.credentialstore.internal.repository;

import eu.exeris.caps.credentialstore.CredentialStoreModule;
import eu.exeris.caps.credentialstore.api.model.CredentialVerificationResult;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.api.model.ProvisionResult;
import eu.exeris.caps.credentialstore.internal.CountingPasswordEncoder;
import eu.exeris.caps.credentialstore.internal.DefaultCredentialProvisioning;
import eu.exeris.caps.credentialstore.internal.DefaultCredentialStore;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.kernel.community.persistence.jdbc.JdbcPersistenceConnection;
import eu.exeris.kernel.spi.exceptions.persistence.PersistenceProviderException;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@code provisionFirstVerified} against a real PostgreSQL: atomicity against concurrent bootstraps and
 * ordinary writers, joining into a host unit, retried units, unmigrated and row-level-secured schemas.
 *
 * <p>Concurrency is scripted: one unit holds its lock on a latch, the contender is observed blocked in
 * {@code pg_stat_activity}, and only then is the holder released. The database settings are the same as for
 * {@link PostgresCredentialRepositoryLiveIT}.
 */
@DisplayName("provisionFirstVerified on a live PostgreSQL")
class PostgresFirstCredentialLiveIT {

    private static final String SCHEMA = "test_first_credential_live";
    private static final String UNMIGRATED = "test_first_credential_unmigrated";
    private static final String RLS_ENABLED = "test_first_credential_rls_enabled";
    private static final String RLS_FORCED = "test_first_credential_rls_forced";
    private static final long WAIT_SECONDS = 60;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    private static String url;
    private static String user;
    private static String password;
    private static PostgreSQLContainer<?> container;
    private static ExecutorService pool;

    private final RecordingEncoder encoder = new RecordingEncoder();
    private final UnitExecutor executor = new UnitExecutor(SCHEMA);
    private final PostgresCredentialRepository repository = new PostgresCredentialRepository(executor);
    private final PasswordHashing hashing = new PasswordHashing(encoder, new KdfConcurrencyThrottler(8));
    private final DefaultCredentialProvisioning provisioning = provisioningOver(repository);
    private final DefaultCredentialStore store = new DefaultCredentialStore(repository, hashing,
            LockoutPolicy.defaults(), PasswordPolicy.defaults(), null, null, Clock.systemUTC());

    private DefaultCredentialProvisioning provisioningOver(CredentialRepository repo) {
        return new DefaultCredentialProvisioning(repo, hashing, PasswordPolicy.defaults(), null, Clock.systemUTC());
    }

    @BeforeAll
    static void setUpDatabase() throws Exception {
        url = setting("EXERIS_TEST_PG_URL", "exeris.test.pg.url");
        user = setting("EXERIS_TEST_PG_USER", "exeris.test.pg.user");
        password = setting("EXERIS_TEST_PG_PASSWORD", "exeris.test.pg.password");
        if (url == null || user == null || password == null) {
            url = user = password = null;
            startContainer();
        }
        pool = Executors.newCachedThreadPool();
        for (String schema : List.of(SCHEMA, UNMIGRATED, RLS_ENABLED, RLS_FORCED)) {
            try (Connection conn = DriverManager.getConnection(url, user, password);
                 Statement stmt = conn.createStatement()) {
                stmt.execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
                stmt.execute("CREATE SCHEMA " + schema);
            }
        }
        migrate(SCHEMA);
        migrate(RLS_ENABLED);
        migrate(RLS_FORCED);
        try (Connection conn = open(RLS_ENABLED); Statement stmt = conn.createStatement()) {
            stmt.execute("ALTER TABLE credential_records ENABLE ROW LEVEL SECURITY");
        }
        try (Connection conn = open(RLS_FORCED); Statement stmt = conn.createStatement()) {
            stmt.execute("ALTER TABLE credential_records FORCE ROW LEVEL SECURITY");
        }
    }

    private static void migrate(String schema) throws Exception {
        try (Connection conn = open(schema); Statement stmt = conn.createStatement()) {
            for (String migration : CredentialStoreModule.MIGRATIONS) {
                for (String statement : statements(read(migration))) {
                    stmt.execute(statement);
                }
            }
        }
    }

    private static void startContainer() {
        boolean required = "true".equalsIgnoreCase(setting("EXERIS_REQUIRE_LIVE_PG", "exeris.test.pg.required"));
        boolean docker;
        try {
            docker = DockerClientFactory.instance().isDockerAvailable();
        } catch (RuntimeException _) {
            docker = false;
        }
        if (!docker) {
            if (required) {
                throw new IllegalStateException("a live PostgreSQL is required (EXERIS_REQUIRE_LIVE_PG) but neither "
                        + "EXERIS_TEST_PG_URL/USER/PASSWORD nor Docker is available");
            }
            Assumptions.abort("no PostgreSQL configured and no Docker");
        }
        container = new PostgreSQLContainer<>("postgres:16");
        container.start();
        url = container.getJdbcUrl();
        user = container.getUsername();
        password = container.getPassword();
    }

    @AfterAll
    static void tearDown() throws SQLException {
        try {
            if (pool != null) {
                pool.shutdownNow();
            }
            if (url != null && user != null && password != null) {
                try (Connection conn = DriverManager.getConnection(url, user, password);
                     Statement stmt = conn.createStatement()) {
                    for (String schema : List.of(SCHEMA, UNMIGRATED, RLS_ENABLED, RLS_FORCED)) {
                        stmt.execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
                    }
                }
            }
        } finally {
            if (container != null) {
                container.stop();
            }
        }
    }

    @BeforeEach
    void emptyTable() throws SQLException {
        try (Connection conn = open(SCHEMA); Statement stmt = conn.createStatement()) {
            stmt.execute("TRUNCATE credential_records CASCADE");
        }
    }

    // ---- helpers -------------------------------------------------------------------------------------

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

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MICROS);
    }

    private static long count(String schema) throws SQLException {
        try (Connection conn = open(schema); Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT count(*) FROM credential_records")) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private static long count() throws SQLException {
        return count(SCHEMA);
    }

    private static long scalar(String sql, String... args) throws SQLException {
        try (Connection conn = open(SCHEMA); PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) {
                ps.setString(i + 1, args[i]);
            }
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    private static long blocked(String queryPrefix) throws SQLException {
        return scalar("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                + "AND wait_event_type = 'Lock' AND query LIKE ?", queryPrefix + "%");
    }

    /** Polls the database until a backend is observed waiting on a lock in a statement starting with the prefix. */
    private static void awaitBlocked(String queryPrefix, Future<?> contender) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
        while (blocked(queryPrefix) == 0) {
            assertThat(contender.isDone()).as("contender returned instead of blocking").isFalse();
            assertThat(System.nanoTime()).as("no backend blocked on " + queryPrefix).isLessThan(deadline);
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
        }
        assertThat(contender.isDone()).as("contender is still waiting").isFalse();
    }

    private static final String LOCK_PREFIX = "LOCK TABLE credential_records";

    /** A host unit that runs the body, then holds its transaction open until released. */
    private final class HeldUnit<T> {
        final CountDownLatch held = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        final Future<T> outcome;

        HeldUnit(Supplier<T> body, boolean failAfter) {
            outcome = pool.submit(() -> executor.inUnit(() -> {
                T value = body.get();
                held.countDown();
                if (!release.await(WAIT_SECONDS, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("holder never released");
                }
                if (failAfter) {
                    throw new IllegalStateException("host rolls back");
                }
                return value;
            }));
        }

        void awaitHeld() throws Exception {
            while (!held.await(20, TimeUnit.MILLISECONDS)) {
                if (outcome.isDone()) {
                    outcome.get();
                    throw new AssertionError("holder finished without holding");
                }
            }
        }

        void release() {
            release.countDown();
        }
    }

    private Future<Optional<ProvisionResult>> contender(UUID subject, String login) {
        return pool.submit(() -> provisioning.provisionFirstVerified(subject, login, newPassword()));
    }

    private static <T> T get(Future<T> future) throws Exception {
        return future.get(WAIT_SECONDS, TimeUnit.SECONDS);
    }

    private void rawInsert(Connection conn, UUID subject, String login) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("INSERT INTO credential_records "
                + "(subject_id, login_identifier, password_hash, created_at, updated_at) VALUES (?, ?, ?, now(), now())")) {
            ps.setObject(1, subject);
            ps.setString(2, login);
            ps.setString(3, "$argon2id$raw");
            ps.executeUpdate();
        }
    }

    // ---- outcomes ------------------------------------------------------------------------------------

    @Test
    @DisplayName("an empty table: the first call creates one verified credential that signs in at once")
    void firstCallCreatesCredential() throws Exception {
        UUID subject = UUID.randomUUID();
        String login = newLogin();
        char[] pw = newPassword();
        char[] same = pw.clone();

        Optional<ProvisionResult> result = provisioning.provisionFirstVerified(subject, login, pw);

        assertThat(result).isPresent();
        assertThat(result.get().subjectId()).isEqualTo(subject);
        assertThat(result.get().loginIdentifier()).isEqualTo(login);
        assertThat(pw).containsOnly('\0');
        assertThat(count()).isEqualTo(1);
        CredentialRecord record = repository.findBySubject(subject).orElseThrow();
        assertThat(record.emailVerified()).isTrue();
        assertThat(scalar("SELECT count(*) FROM account_verification_tokens")).isZero();
        CredentialVerificationResult auth = store.authenticate(login, same);
        assertThat(auth.isSuccess()).isTrue();
        assertThat(auth.subjectId()).isEqualTo(subject);
    }

    @Test
    @DisplayName("an existing credential, unverified or verified, refuses and is left byte-identical")
    void existingCredentialRefuses() throws Exception {
        UUID unverified = UUID.randomUUID();
        UUID verified = UUID.randomUUID();
        String unverifiedLogin = newLogin();
        repository.insertCredential(unverified, unverifiedLogin, "$argon2id$one", now());
        repository.insertVerifiedCredential(verified, newLogin(), "$argon2id$two", now());
        CredentialRecord a = repository.findBySubject(unverified).orElseThrow();
        CredentialRecord b = repository.findBySubject(verified).orElseThrow();

        char[] pw = newPassword();
        assertThat(provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), pw)).isEmpty();
        assertThat(pw).containsOnly('\0');
        assertThat(provisioning.provisionFirstVerified(unverified, newLogin(), newPassword())).isEmpty();
        assertThat(provisioning.provisionFirstVerified(UUID.randomUUID(),
                unverifiedLogin.toUpperCase(java.util.Locale.ROOT), newPassword())).isEmpty();

        assertThat(count()).isEqualTo(2);
        assertThat(repository.findBySubject(unverified)).contains(a);
        assertThat(repository.findBySubject(verified)).contains(b);
    }

    // ---- concurrency ---------------------------------------------------------------------------------

    @Test
    @DisplayName("scripted: while one bootstrap holds its unit the second blocks on the lock, then returns empty")
    void bootstrapAgainstBootstrap() throws Exception {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        HeldUnit<Optional<ProvisionResult>> holder =
                new HeldUnit<>(() -> provisioning.provisionFirstVerified(first, newLogin(), newPassword()), false);
        try {
            holder.awaitHeld();
            assertThat(scalar("SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation "
                    + "WHERE c.relname = 'credential_records' AND l.mode = 'ShareRowExclusiveLock' AND l.granted "
                    + "AND c.relnamespace = to_regnamespace('" + SCHEMA + "')")).isEqualTo(1);

            Future<Optional<ProvisionResult>> contender = contender(second, newLogin());
            awaitBlocked(LOCK_PREFIX, contender);
            holder.release();

            assertThat(get(holder.outcome)).isPresent();
            assertThat(get(contender)).isEmpty();
        } finally {
            holder.release();
        }
        assertThat(count()).isEqualTo(1);
        assertThat(repository.findBySubject(first)).isPresent();
        assertThat(repository.findBySubject(second)).isEmpty();
    }

    @Test
    @DisplayName("free-running: sixteen simultaneous bootstraps yield exactly one result and one credential")
    void sixteenSimultaneousBootstraps() throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Optional<ProvisionResult>>> futures = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), newPassword());
            }));
        }
        start.countDown();
        int present = 0;
        for (Future<Optional<ProvisionResult>> f : futures) {
            present += get(f).isPresent() ? 1 : 0;
        }
        assertThat(present).isEqualTo(1);
        assertThat(count()).isEqualTo(1);
    }

    @Test
    @DisplayName("an uncommitted ordinary insert blocks the bootstrap; its commit makes the bootstrap return empty")
    void uncommittedWriterThatCommits() throws Exception {
        try (Connection writer = open(SCHEMA)) {
            writer.setAutoCommit(false);
            rawInsert(writer, UUID.randomUUID(), newLogin());
            Future<Optional<ProvisionResult>> contender = contender(UUID.randomUUID(), newLogin());
            awaitBlocked(LOCK_PREFIX, contender);
            writer.commit();

            assertThat(get(contender)).isEmpty();
        }
        assertThat(count()).isEqualTo(1);
    }

    @Test
    @DisplayName("an uncommitted ordinary insert that rolls back lets the bootstrap create the first credential")
    void uncommittedWriterThatRollsBack() throws Exception {
        UUID subject = UUID.randomUUID();
        try (Connection writer = open(SCHEMA)) {
            writer.setAutoCommit(false);
            rawInsert(writer, UUID.randomUUID(), newLogin());
            Future<Optional<ProvisionResult>> contender = contender(subject, newLogin());
            awaitBlocked(LOCK_PREFIX, contender);
            writer.rollback();

            assertThat(get(contender)).isPresent();
        }
        assertThat(count()).isEqualTo(1);
        assertThat(repository.findBySubject(subject)).isPresent();
    }

    @Test
    @DisplayName("an uncommitted createCredential in a host unit blocks the bootstrap, which then returns empty")
    void uncommittedCreateCredentialInHostUnit() throws Exception {
        HeldUnit<Void> writer = new HeldUnit<>(() -> {
            store.createCredential(UUID.randomUUID(), newLogin(), newPassword());
            return null;
        }, false);
        try {
            writer.awaitHeld();
            Future<Optional<ProvisionResult>> contender = contender(UUID.randomUUID(), newLogin());
            awaitBlocked(LOCK_PREFIX, contender);
            writer.release();
            get(writer.outcome);
            assertThat(get(contender)).isEmpty();
        } finally {
            writer.release();
        }
        assertThat(count()).isEqualTo(1);
    }

    @Test
    @DisplayName("an uncommitted provisionVerified in a host unit blocks the bootstrap, which then returns empty")
    void uncommittedProvisionVerifiedInHostUnit() throws Exception {
        HeldUnit<ProvisionResult> writer = new HeldUnit<>(
                () -> provisioning.provisionVerified(UUID.randomUUID(), newLogin(), newPassword()), false);
        try {
            writer.awaitHeld();
            Future<Optional<ProvisionResult>> contender = contender(UUID.randomUUID(), newLogin());
            awaitBlocked(LOCK_PREFIX, contender);
            writer.release();
            get(writer.outcome);
            assertThat(get(contender)).isEmpty();
        } finally {
            writer.release();
        }
        assertThat(count()).isEqualTo(1);
    }

    @Test
    @DisplayName("while a bootstrap holds the lock an ordinary writer waits until the host unit ends, then inserts")
    void ordinaryWriterWaitsForBootstrap() throws Exception {
        HeldUnit<Optional<ProvisionResult>> holder = new HeldUnit<>(
                () -> provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), newPassword()), false);
        try {
            holder.awaitHeld();
            Future<?> writer = pool.submit(() -> store.createCredential(UUID.randomUUID(), newLogin(), newPassword()));
            awaitBlocked("INSERT INTO credential_records", writer);
            holder.release();
            get(holder.outcome);
            get(writer);
        } finally {
            holder.release();
        }
        assertThat(count()).isEqualTo(2);
    }

    @Test
    @DisplayName("a rolled-back first bootstrap lets the waiting second bootstrap create the first credential")
    void rollbackOfTheFirst() throws Exception {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        HeldUnit<Optional<ProvisionResult>> holder = new HeldUnit<>(
                () -> provisioning.provisionFirstVerified(first, newLogin(), newPassword()), true);
        try {
            holder.awaitHeld();
            Future<Optional<ProvisionResult>> contender = contender(second, newLogin());
            awaitBlocked(LOCK_PREFIX, contender);
            holder.release();

            assertThatThrownBy(() -> get(holder.outcome)).hasRootCauseMessage("host rolls back");
            assertThat(get(contender)).isPresent();
        } finally {
            holder.release();
        }
        assertThat(count()).isEqualTo(1);
        assertThat(repository.findBySubject(first)).isEmpty();
        assertThat(repository.findBySubject(second)).isPresent();
    }

    @Test
    @DisplayName("reads on the request path do not block while a bootstrap holds its lock")
    void readsAreNotBlocked() throws Exception {
        UUID subject = UUID.randomUUID();
        String login = newLogin();
        HeldUnit<Optional<ProvisionResult>> holder = new HeldUnit<>(
                () -> provisioning.provisionFirstVerified(subject, login, newPassword()), false);
        try {
            holder.awaitHeld();
            Future<Boolean> read = pool.submit(() -> repository.findByLoginIdentifier(login).isEmpty()
                    && repository.findBySubject(subject).isEmpty()
                    && store.authenticate(login, newPassword()).isInvalid());
            assertThat(get(read)).as("uncommitted row invisible, reads completed under the lock").isTrue();
            assertThat(holder.outcome.isDone()).isFalse();
            holder.release();
            get(holder.outcome);
        } finally {
            holder.release();
        }
        assertThat(repository.findByLoginIdentifier(login)).isPresent();
    }

    // ---- joining and retry ---------------------------------------------------------------------------

    @Test
    @DisplayName("inside a host unit the credential is visible to others only after the host commits")
    void visibleOnlyAfterHostCommit() throws Exception {
        UUID subject = UUID.randomUUID();
        Optional<ProvisionResult> result = executor.inUnit(() -> {
            Optional<ProvisionResult> r = provisioning.provisionFirstVerified(subject, newLogin(), newPassword());
            try {
                assertThat(count()).as("other connection, before the host commits").isZero();
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
            return r;
        });

        assertThat(result).isPresent();
        assertThat(count()).isEqualTo(1);
        assertThat(repository.findBySubject(subject)).isPresent();
    }

    @Test
    @DisplayName("a host unit that throws after the call leaves no credential")
    void hostRollbackLeavesNothing() throws Exception {
        assertThatThrownBy(() -> executor.inUnit(() -> {
            provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), newPassword());
            throw new IllegalStateException("host failure after the call");
        })).isInstanceOf(IllegalStateException.class).hasMessage("host failure after the call");

        assertThat(count()).isZero();
        assertThat(provisioning.provisionFirstVerified(UUID.randomUUID(), newLogin(), newPassword())).isPresent();
    }

    @Test
    @DisplayName("a unit that runs twice stores a hash of the original password, one credential")
    void retriedUnitStoresTheOriginalPasswordHash() throws Exception {
        RetryOnceExecutor retrying = new RetryOnceExecutor(SCHEMA);
        DefaultCredentialProvisioning viaRetry = provisioningOver(new PostgresCredentialRepository(retrying));
        UUID subject = UUID.randomUUID();
        String login = newLogin();
        char[] pw = newPassword();
        char[] fresh = pw.clone();

        Optional<ProvisionResult> result = viaRetry.provisionFirstVerified(subject, login, pw);

        assertThat(retrying.attempts()).as("the work ran twice").isEqualTo(2);
        assertThat(result).isPresent();
        assertThat(pw).containsOnly('\0');
        assertThat(count()).isEqualTo(1);
        assertThat(store.authenticate(login, fresh).isSuccess()).isTrue();
    }

    // ---- schema and tenancy --------------------------------------------------------------------------

    @Test
    @DisplayName("an unmigrated schema fails with SQLSTATE 42P01, writes nothing and zeroes the array")
    void unmigratedSchema() throws Exception {
        PostgresCredentialRepository repo = new PostgresCredentialRepository(new UnitExecutor(UNMIGRATED));
        DefaultCredentialProvisioning unmigrated = provisioningOver(repo);
        char[] pw = newPassword();

        assertThatThrownBy(() -> unmigrated.provisionFirstVerified(UUID.randomUUID(), newLogin(), pw))
                .isInstanceOf(PersistenceProviderException.class)
                .satisfies(e -> assertThat(Arrays.deepToString(((PersistenceProviderException) e).rawArgs()))
                        .contains("42P01"));

        assertThat(pw).containsOnly('\0');
        assertThat(scalar("SELECT count(*) FROM information_schema.tables WHERE table_schema = '" + UNMIGRATED + "'"))
                .isZero();
    }

    @Test
    @DisplayName("row-level security, enabled or forced, is refused with IllegalStateException and nothing is written")
    void rowLevelSecurityRefused() throws Exception {
        for (String schema : List.of(RLS_ENABLED, RLS_FORCED)) {
            DefaultCredentialProvisioning secured =
                    provisioningOver(new PostgresCredentialRepository(new UnitExecutor(schema)));
            char[] pw = newPassword();

            assertThatThrownBy(() -> secured.provisionFirstVerified(UUID.randomUUID(), newLogin(), pw))
                    .as(schema).isInstanceOf(IllegalStateException.class);

            assertThat(pw).as(schema).containsOnly('\0');
            assertThat(count(schema)).as(schema).isZero();
        }
    }

    // ---- disclosure ----------------------------------------------------------------------------------

    @Test
    @DisplayName("neither log records nor exception messages carry the login, the password or the hash")
    void noDisclosureOnAnyPath() throws Exception {
        List<String> logged = new CopyOnWriteArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                logged.add(new SimpleFormatter().formatMessage(record)
                        + (record.getThrown() == null ? "" : " " + record.getThrown()));
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        Logger root = Logger.getLogger("");
        root.addHandler(handler);
        List<String> secrets = new ArrayList<>();
        List<String> messages = new ArrayList<>();
        try {
            secrets.addAll(run(provisioning, messages));
            secrets.addAll(run(provisioningOver(new PostgresCredentialRepository(new UnitExecutor(UNMIGRATED))), messages));
            secrets.addAll(run(provisioningOver(new PostgresCredentialRepository(new UnitExecutor(RLS_ENABLED))), messages));
        } finally {
            root.removeHandler(handler);
        }

        assertThat(secrets).isNotEmpty();
        for (String secret : secrets) {
            assertThat(logged).noneMatch(line -> line.contains(secret));
            assertThat(messages).noneMatch(line -> line.contains(secret));
        }
        assertThat(encoder.hashes).isNotEmpty();
    }

    /** Calls the operation twice (a first call, and a refused or failing one), returning the secrets used. */
    private List<String> run(DefaultCredentialProvisioning target, List<String> messages) {
        List<String> secrets = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            String login = newLogin();
            char[] pw = newPassword();
            secrets.add(login);
            secrets.add(new String(pw));
            try {
                target.provisionFirstVerified(UUID.randomUUID(), login, pw);
            } catch (RuntimeException e) {
                for (Throwable t = e; t != null; t = t.getCause()) {
                    messages.add(t + " " + t.getMessage());
                }
            }
        }
        secrets.addAll(encoder.hashes);
        return secrets;
    }

    // ---- infrastructure ------------------------------------------------------------------------------

    private static String setting(String env, String property) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) {
            value = System.getenv(env);
        }
        return value == null || value.isBlank() ? null : value;
    }

    private static Connection open(String schema) throws SQLException {
        String separator = url.contains("?") ? "&" : "?";
        return DriverManager.getConnection(url + separator + "currentSchema=" + schema, user, password);
    }

    private static String read(String resource) throws IOException {
        try (InputStream in = PostgresFirstCredentialLiveIT.class.getClassLoader().getResourceAsStream(resource)) {
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

    /** Records every hash the capability derives, so a test can look for it in logs and messages. */
    private static final class RecordingEncoder implements KernelPasswordEncoder {
        private final CountingPasswordEncoder delegate = new CountingPasswordEncoder();
        final List<String> hashes = new CopyOnWriteArrayList<>();

        @Override
        public String encode(char[] raw) {
            String hash = delegate.encode(raw);
            hashes.add(hash);
            return hash;
        }

        @Override
        public boolean matches(char[] raw, String encoded) {
            return delegate.matches(raw, encoded);
        }
    }

    /**
     * One JDBC connection per unit of work, as the kernel executor does, plus {@link #inUnit}, which plays the
     * host: work run inside it joins the host's connection and transaction instead of opening its own.
     */
    private static class UnitExecutor implements TransactionalExecutor {
        private final String schema;
        private final ThreadLocal<PersistenceConnection> current = new ThreadLocal<>();

        UnitExecutor(String schema) {
            this.schema = schema;
        }

        <T> T inUnit(Callable<T> body) throws Exception {
            try (Connection jdbc = open(schema)) {
                PersistenceConnection conn = new JdbcPersistenceConnection(jdbc);
                conn.beginTransaction();
                current.set(conn);
                try {
                    T value = body.call();
                    conn.commit();
                    return value;
                } catch (Throwable t) {
                    conn.rollback();
                    throw t;
                } finally {
                    current.remove();
                }
            }
        }

        @Override
        public void execute(TransactionalWork work) {
            executeManaged(work);
        }

        @Override
        public void executeManaged(TransactionalWork work) {
            PersistenceConnection joined = current.get();
            if (joined != null) {
                work.run(joined);
                return;
            }
            try (Connection jdbc = open(schema)) {
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
            PersistenceConnection joined = current.get();
            if (joined != null) {
                return query.apply(joined);
            }
            try (Connection jdbc = open(schema)) {
                return query.apply(new JdbcPersistenceConnection(jdbc));
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /** Runs each unit of work, rolls it back as a retryable failure would, and runs it again to commit. */
    private static final class RetryOnceExecutor extends UnitExecutor {
        private final String schema;
        private int attempts;

        RetryOnceExecutor(String schema) {
            super(schema);
            this.schema = schema;
        }

        int attempts() {
            return attempts;
        }

        @Override
        public void executeManaged(TransactionalWork work) {
            try (Connection jdbc = open(schema)) {
                PersistenceConnection conn = new JdbcPersistenceConnection(jdbc);
                for (int attempt = 1; attempt <= 2; attempt++) {
                    attempts++;
                    conn.beginTransaction();
                    work.run(conn);
                    if (attempt == 1) {
                        conn.rollback();
                    } else {
                        conn.commit();
                    }
                }
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
