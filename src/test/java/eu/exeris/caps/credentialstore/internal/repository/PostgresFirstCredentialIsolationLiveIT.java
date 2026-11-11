package eu.exeris.caps.credentialstore.internal.repository;

import eu.exeris.caps.credentialstore.CredentialStoreModule;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.api.model.ProvisionResult;
import eu.exeris.caps.credentialstore.internal.CountingPasswordEncoder;
import eu.exeris.caps.credentialstore.internal.DefaultCredentialProvisioning;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.kernel.community.persistence.jdbc.JdbcPersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
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
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exclusion of concurrent first credentials at every isolation level.
 *
 * <p>Two callers on an empty table: exactly one creates a credential and the other gets an empty result, at
 * {@code READ COMMITTED}, {@code REPEATABLE READ} and {@code SERIALIZABLE}, provided the call is the first
 * statement of its transaction. At the two snapshot levels the snapshot is fixed by the first query, so the
 * table lock has to be taken before any read; the raw-JDBC controls pin that reason independent of the class.
 *
 * <p>Every synchronisation is a poll of {@code pg_stat_activity}; nothing sleeps for a fixed time.
 */
@DisplayName("provisionFirstVerified: first-credential exclusion at every isolation level")
class PostgresFirstCredentialIsolationLiveIT {

    private static final String SCHEMA = "test_first_credential_isolation";
    private static final String LOCK_PREFIX = "LOCK TABLE credential_records";
    private static final long WAIT_SECONDS = 60;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    private static String url;
    private static String user;
    private static String password;
    private static PostgreSQLContainer<?> container;
    private static ExecutorService pool;

    private final PasswordHashing hashing =
            new PasswordHashing(new CountingPasswordEncoder(), new KdfConcurrencyThrottler(8));

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
        try (Connection conn = DriverManager.getConnection(url, user, password);
             Statement stmt = conn.createStatement()) {
            stmt.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
            stmt.execute("CREATE SCHEMA " + SCHEMA);
        }
        try (Connection conn = open(); Statement stmt = conn.createStatement()) {
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
                    stmt.execute("DROP SCHEMA IF EXISTS " + SCHEMA + " CASCADE");
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
        try (Connection conn = open(); Statement stmt = conn.createStatement()) {
            stmt.execute("TRUNCATE credential_records CASCADE");
        }
    }

    // ---- two callers, through the public operation ---------------------------------------------------

    @Test
    @DisplayName("READ COMMITTED: the second caller waits on the lock, then returns empty; one row")
    void twoCallersReadCommitted() throws Exception {
        twoCallers(TransactionIsolation.READ_COMMITTED, "read committed");
    }

    @Test
    @DisplayName("REPEATABLE READ: the second caller waits on the lock, then returns empty; one row")
    void twoCallersRepeatableRead() throws Exception {
        twoCallers(TransactionIsolation.REPEATABLE_READ, "repeatable read");
    }

    @Test
    @DisplayName("SERIALIZABLE: the second caller waits on the lock, then returns empty; one row")
    void twoCallersSerializable() throws Exception {
        twoCallers(TransactionIsolation.SERIALIZABLE, "serializable");
    }

    /**
     * Caller A runs the operation as the first statement of a transaction at the level and is parked after
     * the insert and before the commit. Caller B is started and observed blocked on the table lock. A commits,
     * then B completes.
     */
    private void twoCallers(TransactionIsolation level, String expectedLevel) throws Exception {
        LevelExecutor executorA = new LevelExecutor(level, true);
        LevelExecutor executorB = new LevelExecutor(level, false);
        UUID subjectA = UUID.randomUUID();
        UUID subjectB = UUID.randomUUID();

        Future<Optional<ProvisionResult>> a = pool.submit(
                () -> provisioningOver(executorA).provisionFirstVerified(subjectA, newLogin(), newPassword()));
        executorA.awaitParked(a);
        assertThat(count()).as("A is parked before commit: nothing visible yet").isZero();

        Future<Optional<ProvisionResult>> b = pool.submit(
                () -> provisioningOver(executorB).provisionFirstVerified(subjectB, newLogin(), newPassword()));
        awaitBlocked(LOCK_PREFIX, b);

        executorA.releaseCommit();
        Optional<ProvisionResult> resultA = get(a);
        Optional<ProvisionResult> resultB;
        try {
            resultB = get(b);
        } catch (ExecutionException e) {
            throw new AssertionError("B failed at " + expectedLevel + " instead of returning empty: " + e.getCause(),
                    e.getCause());
        }

        assertThat(executorA.observedIsolation()).as("A's transaction level").isEqualTo(expectedLevel);
        assertThat(executorB.observedIsolation()).as("B's transaction level").isEqualTo(expectedLevel);
        assertThat(resultA).as("A created the credential").isPresent();
        assertThat(resultA.get().subjectId()).isEqualTo(subjectA);
        assertThat(resultB).as("B saw A's committed credential").isEmpty();
        assertThat(count()).isEqualTo(1);
        assertThat(scalar("SELECT count(*) FROM credential_records WHERE subject_id = '" + subjectA + "'")).isEqualTo(1);
    }

    // ---- control: the order of statements, on raw JDBC -----------------------------------------------

    @Test
    @DisplayName("control, old order (catalog read, lock, existence read, insert) at REPEATABLE READ: two rows")
    void controlOldOrderRepeatableReadCreatesTwo() throws Exception {
        assertThat(rawTwoCallers(false, Connection.TRANSACTION_REPEATABLE_READ)).isEqualTo(2);
    }

    @Test
    @DisplayName("control, new order (lock, catalog read, existence read, insert) at REPEATABLE READ: one row")
    void controlNewOrderRepeatableReadCreatesOne() throws Exception {
        assertThat(rawTwoCallers(true, Connection.TRANSACTION_REPEATABLE_READ)).isEqualTo(1);
    }

    @Test
    @DisplayName("control, old order at READ COMMITTED: one row, each statement takes its own snapshot")
    void controlOldOrderReadCommittedCreatesOne() throws Exception {
        assertThat(rawTwoCallers(false, Connection.TRANSACTION_READ_COMMITTED)).isEqualTo(1);
    }

    /**
     * Two raw-JDBC callers with the production SQL, in the given order. Returns the number of rows left.
     * A holds its transaction after the insert; B is observed blocked on the lock; then A commits.
     */
    private int rawTwoCallers(boolean lockFirst, int jdbcLevel) throws Exception {
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<Boolean> a = pool.submit(() -> rawCaller(lockFirst, jdbcLevel, () -> {
            held.countDown();
            if (!release.await(WAIT_SECONDS, TimeUnit.SECONDS)) {
                throw new IllegalStateException("holder never released");
            }
        }));
        try {
            while (!held.await(20, TimeUnit.MILLISECONDS)) {
                if (a.isDone()) {
                    a.get();
                    throw new AssertionError("A finished without holding");
                }
            }
            Future<Boolean> b = pool.submit(() -> rawCaller(lockFirst, jdbcLevel, () -> { }));
            awaitBlocked(LOCK_PREFIX, b);
            release.countDown();
            assertThat(get(a)).as("A inserted").isTrue();
            get(b);
        } finally {
            release.countDown();
        }
        return (int) count();
    }

    /** One caller: begin at the level, run the statements in order, hook, commit. True if it inserted. */
    private boolean rawCaller(boolean lockFirst, int jdbcLevel, Hook beforeCommit) throws Exception {
        try (Connection conn = open()) {
            conn.setTransactionIsolation(jdbcLevel);
            conn.setAutoCommit(false);
            try {
                if (!lockFirst) {
                    rawQuery(conn, PostgresCredentialRepository.RLS_STATE);
                }
                try (Statement stmt = conn.createStatement()) {
                    stmt.execute(PostgresCredentialRepository.LOCK_FOR_FIRST);
                }
                if (lockFirst) {
                    rawQuery(conn, PostgresCredentialRepository.RLS_STATE);
                }
                boolean inserted = false;
                if (!rawQuery(conn, PostgresCredentialRepository.ANY_CREDENTIAL)) {
                    rawInsertVerified(conn);
                    inserted = true;
                }
                beforeCommit.run();
                conn.commit();
                return inserted;
            } catch (Exception | Error e) {
                conn.rollback();
                throw e;
            }
        }
    }

    @FunctionalInterface
    private interface Hook {
        void run() throws Exception;
    }

    private static boolean rawQuery(Connection conn, String sql) throws SQLException {
        try (Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            return rs.next() && rs.getBoolean(1);
        }
    }

    private static void rawInsertVerified(Connection conn) throws SQLException {
        String sql = PostgresCredentialRepository.INSERT_VERIFIED_CREDENTIAL.replaceAll("\\$\\d+", "?");
        OffsetDateTime now = OffsetDateTime.now();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setObject(1, UUID.randomUUID());
            ps.setString(2, newLogin());
            ps.setString(3, "$argon2id$raw");
            ps.setObject(4, now);
            ps.setObject(5, now);
            ps.setObject(6, now);
            ps.executeUpdate();
        }
    }

    // ---- documented limit ----------------------------------------------------------------------------

    @Test
    @DisplayName("DOCUMENTED LIMIT, not desired behaviour: a REPEATABLE READ host that already read can add a second first credential")
    void documentedLimitJoinedRepeatableReadAfterAReadCreatesASecondCredential() throws Exception {
        LevelExecutor host = new LevelExecutor(TransactionIsolation.REPEATABLE_READ, false);
        DefaultCredentialProvisioning joined = provisioningOver(host);
        LevelExecutor other = new LevelExecutor(TransactionIsolation.REPEATABLE_READ, false);

        Optional<ProvisionResult> hostResult = host.inUnit(TransactionIsolation.REPEATABLE_READ, () -> {
            assertThat(host.countRows()).as("the host's own query fixes its snapshot on an empty table").isZero();
            Optional<ProvisionResult> concurrent = provisioningOver(other)
                    .provisionFirstVerified(UUID.randomUUID(), newLogin(), newPassword());
            assertThat(concurrent).as("another caller commits the first credential in between").isPresent();
            return joined.provisionFirstVerified(UUID.randomUUID(), newLogin(), newPassword());
        });

        assertThat(hostResult).as("the joined call acts on the stale snapshot").isPresent();
        assertThat(count()).as("two first credentials: the stated limit").isEqualTo(2);
    }

    @Test
    @DisplayName("a READ COMMITTED host that already read is still excluded: the joined call returns empty")
    void joinedReadCommittedAfterAReadIsExcluded() throws Exception {
        LevelExecutor host = new LevelExecutor(TransactionIsolation.READ_COMMITTED, false);
        DefaultCredentialProvisioning joined = provisioningOver(host);
        LevelExecutor other = new LevelExecutor(TransactionIsolation.READ_COMMITTED, false);

        Optional<ProvisionResult> hostResult = host.inUnit(TransactionIsolation.READ_COMMITTED, () -> {
            assertThat(host.countRows()).isZero();
            assertThat(provisioningOver(other)
                    .provisionFirstVerified(UUID.randomUUID(), newLogin(), newPassword())).isPresent();
            return joined.provisionFirstVerified(UUID.randomUUID(), newLogin(), newPassword());
        });

        assertThat(hostResult).isEmpty();
        assertThat(count()).isEqualTo(1);
    }

    // ---- helpers -------------------------------------------------------------------------------------

    private DefaultCredentialProvisioning provisioningOver(TransactionalExecutor executor) {
        return new DefaultCredentialProvisioning(new PostgresCredentialRepository(executor), hashing,
                PasswordPolicy.defaults(), null, Clock.systemUTC());
    }

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

    private static <T> T get(Future<T> future) throws Exception {
        return future.get(WAIT_SECONDS, TimeUnit.SECONDS);
    }

    private static long count() throws SQLException {
        return scalar("SELECT count(*) FROM credential_records");
    }

    private static long scalar(String sql, String... args) throws SQLException {
        try (Connection conn = open(); PreparedStatement ps = conn.prepareStatement(sql)) {
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

    private static String setting(String env, String property) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) {
            value = System.getenv(env);
        }
        return value == null || value.isBlank() ? null : value;
    }

    private static Connection open() throws SQLException {
        String separator = url.contains("?") ? "&" : "?";
        return DriverManager.getConnection(url + separator + "currentSchema=" + SCHEMA, user, password);
    }

    private static String read(String resource) throws IOException {
        try (InputStream in = PostgresFirstCredentialIsolationLiveIT.class.getClassLoader()
                .getResourceAsStream(resource)) {
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

    /**
     * One JDBC connection per unit of work, begun at a fixed isolation level as the kernel executor does.
     * Optionally parks the unit after its work and before the commit, and {@link #inUnit} plays a host whose
     * transaction the work joins.
     */
    private static final class LevelExecutor implements TransactionalExecutor {
        private final TransactionIsolation level;
        private final boolean park;
        private final CountDownLatch parked = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private final ThreadLocal<PersistenceConnection> current = new ThreadLocal<>();
        private volatile String observed;

        LevelExecutor(TransactionIsolation level, boolean park) {
            this.level = level;
            this.park = park;
        }

        String observedIsolation() {
            return observed;
        }

        void awaitParked(Future<?> unit) throws Exception {
            while (!parked.await(20, TimeUnit.MILLISECONDS)) {
                if (unit.isDone()) {
                    unit.get();
                    throw new AssertionError("the unit finished without parking");
                }
            }
        }

        void releaseCommit() {
            release.countDown();
        }

        long countRows() {
            return query(conn -> {
                try (QueryResult rs = conn.executeQuery("SELECT count(*) FROM credential_records")) {
                    rs.next();
                    return rs.row().getLong(0);
                }
            });
        }

        <T> T inUnit(TransactionIsolation isolation, Callable<T> body) throws Exception {
            try (Connection jdbc = open()) {
                PersistenceConnection conn = new JdbcPersistenceConnection(jdbc);
                conn.beginTransaction(isolation, false);
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
            try (Connection jdbc = open()) {
                PersistenceConnection conn = new JdbcPersistenceConnection(jdbc);
                conn.beginTransaction(level, false);
                try {
                    work.run(conn);
                    try (Statement stmt = jdbc.createStatement();
                         ResultSet rs = stmt.executeQuery("SHOW transaction_isolation")) {
                        rs.next();
                        observed = rs.getString(1);
                    }
                    if (park) {
                        parked.countDown();
                        if (!release.await(WAIT_SECONDS, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("parked unit never released");
                        }
                    }
                    conn.commit();
                } catch (RuntimeException e) {
                    conn.rollback();
                    throw e;
                } catch (InterruptedException e) {
                    conn.rollback();
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
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
            try (Connection jdbc = open()) {
                return query.apply(new JdbcPersistenceConnection(jdbc));
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
