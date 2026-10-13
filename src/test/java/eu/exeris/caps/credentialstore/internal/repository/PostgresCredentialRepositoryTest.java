package eu.exeris.caps.credentialstore.internal.repository;

import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("PostgresCredentialRepository Unit Tests")
class PostgresCredentialRepositoryTest {

    private CapturingTransactionalExecutor tx;
    private PostgresCredentialRepository repository;

    @BeforeEach
    void setUp() {
        tx = new CapturingTransactionalExecutor();
        repository = new PostgresCredentialRepository(tx);
    }

    @Test
    @DisplayName("saveCredential executes managed insert with correct parameters")
    void saveCredentialExecutesManagedInsert() {
        UUID subjectId = UUID.randomUUID();
        String hash = "$argon2id$v=19$m=65536,t=3,p=1$...";
        Instant now = Instant.now();

        repository.saveCredential(subjectId, hash, now);

        assertThat(tx.executedStatements).hasSize(1);
        CapturingStatement stmt = tx.executedStatements.get(0);
        assertThat(stmt.sql).contains("INSERT INTO credential_records");
        assertThat(stmt.boundParameters.get(0)).isEqualTo(subjectId);
        assertThat(stmt.boundParameters.get(1)).isEqualTo(hash);
        assertThat(stmt.boundParameters.get(2)).isEqualTo(now);
        assertThat(stmt.boundParameters.get(3)).isEqualTo(now);
    }

    @Test
    @DisplayName("findCredential reads and maps row cursor fields correctly")
    void findCredentialMapsRowCursor() {
        UUID subjectId = UUID.randomUUID();
        String hash = "hash123";
        Instant verifiedAt = Instant.now();
        Instant lockedUntil = Instant.now().plusSeconds(300);
        Instant createdAt = Instant.now().minusSeconds(1000);
        Instant updatedAt = Instant.now();

        Object[] rowData = new Object[]{subjectId, hash, true, verifiedAt, 2, lockedUntil, 4L, createdAt, updatedAt};
        tx.queryResultSupplier = () -> new StubQueryResult(java.util.Collections.singletonList(rowData));

        Optional<CredentialRecord> result = repository.findCredential(subjectId);

        assertThat(result).isPresent();
        CredentialRecord record = result.get();
        assertThat(record.subjectId()).isEqualTo(subjectId);
        assertThat(record.passwordHash()).isEqualTo(hash);
        assertThat(record.emailVerified()).isTrue();
        assertThat(record.verifiedAt()).isEqualTo(verifiedAt);
        assertThat(record.failedLoginAttempts()).isEqualTo(2);
        assertThat(record.lockedUntil()).isEqualTo(lockedUntil);
        assertThat(record.tokenVersion()).isEqualTo(4L);
        assertThat(record.createdAt()).isEqualTo(createdAt);
        assertThat(record.updatedAt()).isEqualTo(updatedAt);
    }

    @Test
    @DisplayName("updatePassword sets new hash, token_version, and resets lockout")
    void updatePasswordExecutesUpdate() {
        UUID subjectId = UUID.randomUUID();
        String newHash = "newHash";
        Instant now = Instant.now();

        repository.updatePassword(subjectId, newHash, 3L, now);

        assertThat(tx.executedStatements).hasSize(1);
        CapturingStatement stmt = tx.executedStatements.get(0);
        assertThat(stmt.sql).contains("UPDATE credential_records");
        assertThat(stmt.boundParameters.get(0)).isEqualTo(newHash);
        assertThat(stmt.boundParameters.get(1)).isEqualTo(3L);
        assertThat(stmt.boundParameters.get(2)).isEqualTo(now);
        assertThat(stmt.boundParameters.get(3)).isEqualTo(subjectId);
    }

    @Test
    @DisplayName("consumeVerificationToken returns true when rows are affected")
    void consumeVerificationTokenSuccess() {
        UUID tokenId = UUID.randomUUID();
        Instant now = Instant.now();
        tx.rowsAffectedResult = 1L;

        boolean consumed = repository.consumeVerificationToken(tokenId, now);

        assertThat(consumed).isTrue();
        CapturingStatement stmt = tx.executedStatements.get(0);
        assertThat(stmt.sql).contains("UPDATE account_verification_tokens");
        assertThat(stmt.boundParameters.get(0)).isEqualTo(now);
        assertThat(stmt.boundParameters.get(1)).isEqualTo(tokenId);
    }

    @Test
    @DisplayName("consumeResetToken returns false on double spend (0 rows affected)")
    void consumeResetTokenDoubleSpendReturnsFalse() {
        UUID tokenId = UUID.randomUUID();
        Instant now = Instant.now();
        tx.rowsAffectedResult = 0L;

        boolean consumed = repository.consumeResetToken(tokenId, now);

        assertThat(consumed).isFalse();
    }

    // =========================================================================
    // Test Doubles for TransactionalExecutor & Persistence SPI
    // =========================================================================

    private static final class CapturingTransactionalExecutor implements TransactionalExecutor {
        final List<CapturingStatement> executedStatements = new ArrayList<>();
        java.util.function.Supplier<QueryResult> queryResultSupplier;
        long rowsAffectedResult = 1L;

        @Override
        public void execute(TransactionalWork work) {
            work.run(new CapturingConnection(this));
        }

        @Override
        public void executeManaged(TransactionalWork work) {
            work.run(new CapturingConnection(this));
        }

        @Override
        public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
            work.run(new CapturingConnection(this));
        }

        @Override
        public <T> T query(Function<PersistenceConnection, T> query) {
            return query.apply(new CapturingConnection(this));
        }
    }

    private static final class CapturingConnection implements PersistenceConnection {
        private final CapturingTransactionalExecutor executor;

        CapturingConnection(CapturingTransactionalExecutor executor) {
            this.executor = executor;
        }

        @Override
        public PersistenceStatement prepare(String sql) {
            CapturingStatement stmt = new CapturingStatement(sql, executor);
            executor.executedStatements.add(stmt);
            return stmt;
        }

        @Override public QueryResult executeQuery(String sql) { return null; }
        @Override public long executeUpdate(String sql) { return 0; }
        @Override public void beginTransaction() {}
        @Override public void beginTransaction(TransactionIsolation isolation, boolean readOnly) {}
        @Override public void commit() {}
        @Override public void rollback() {}
        @Override public boolean inTransaction() { return true; }
        @Override public boolean isOpen() { return true; }
        @Override public void close() {}
    }

    private static final class CapturingStatement implements PersistenceStatement {
        final String sql;
        final CapturingTransactionalExecutor executor;
        final Map<Integer, Object> boundParameters = new HashMap<>();

        CapturingStatement(String sql, CapturingTransactionalExecutor executor) {
            this.sql = sql;
            this.executor = executor;
        }

        @Override public PersistenceStatement bindInt(int index, int value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindLong(int index, long value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindShort(int index, short value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindFloat(int index, float value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindDouble(int index, double value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindBoolean(int index, boolean value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindString(int index, String value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindUuid(int index, UUID value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindBytes(int index, byte[] value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindInstant(int index, Instant value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindNull(int index) { boundParameters.put(index, null); return this; }

        @Override
        public QueryResult executeQuery() {
            if (executor.queryResultSupplier != null) {
                return executor.queryResultSupplier.get();
            }
            return new StubQueryResult(List.of());
        }

        @Override
        public long executeUpdate() {
            return executor.rowsAffectedResult;
        }

        @Override
        public void close() {}
    }

    private static final class StubQueryResult implements QueryResult {
        private final List<Object[]> rows;
        private int cursor = -1;

        StubQueryResult(List<Object[]> rows) {
            this.rows = rows;
        }

        @Override
        public boolean next() {
            cursor++;
            return cursor < rows.size();
        }

        @Override
        public RowCursor row() {
            return new StubRowCursor(rows.get(cursor));
        }

        @Override public long rowsAffected() { return rows.size(); }
        @Override public int columnCount() { return rows.isEmpty() ? 0 : rows.get(0).length; }
        @Override public String commandTag() { return "SELECT"; }
        @Override public void close() {}
    }

    private static final class StubRowCursor implements RowCursor {
        private final Object[] values;

        StubRowCursor(Object[] values) {
            this.values = values;
        }

        @Override public int getInt(int column) { return (Integer) values[column]; }
        @Override public long getLong(int column) { return (Long) values[column]; }
        @Override public short getShort(int column) { return (Short) values[column]; }
        @Override public float getFloat(int column) { return (Float) values[column]; }
        @Override public double getDouble(int column) { return (Double) values[column]; }
        @Override public boolean getBoolean(int column) { return (Boolean) values[column]; }
        @Override public boolean isNull(int column) { return values[column] == null; }
        @Override public java.lang.foreign.MemorySegment getSegment(int column) { return null; }
        @Override public int getLength(int column) { return 0; }
        @Override public String getString(int column) { return (String) values[column]; }
        @Override public byte[] getBytes(int column) { return (byte[]) values[column]; }
        @Override public UUID getUuid(int column) { return (UUID) values[column]; }
        @Override public Instant getInstant(int column) { return (Instant) values[column]; }
        @Override public int columnCount() { return values.length; }
        @Override public boolean isValid() { return true; }
    }
}
