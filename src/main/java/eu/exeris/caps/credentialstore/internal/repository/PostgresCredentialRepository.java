package eu.exeris.caps.credentialstore.internal.repository;

import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * PostgreSQL implementation of {@link CredentialRepository} over the kernel Persistence SPI. The schema is
 * {@code db/migration/exeris-caps-credential-store/V1__create_credential_store.sql}.
 *
 * <p>Each placeholder appears exactly once and in ascending order: the Community binding translates
 * {@code $n} to positional JDBC {@code ?} markers, so a repeated or out-of-order placeholder would bind the
 * wrong value. A statement that needs a value twice selects it once into a derived table {@code p}.
 *
 * <p>The executor may run a unit of work more than once on a serialization failure, so every result holder
 * is reset at the start of the unit rather than only where it is declared.
 */
public final class PostgresCredentialRepository implements CredentialRepository {

    private static final String COLUMNS =
            "subject_id, login_identifier, password_hash, email_verified, verified_at, failed_login_attempts, "
            + "failure_window_started_at, locked_until, token_version, created_at, updated_at";

    private static final String RETURNING_COLUMNS = " RETURNING c.subject_id, c.login_identifier, c.password_hash, "
            + "c.email_verified, c.verified_at, c.failed_login_attempts, c.failure_window_started_at, "
            + "c.locked_until, c.token_version, c.created_at, c.updated_at";

    /** True when the failure count starts again: no window yet, the window closed, or a lockout ended. */
    private static final String RESTART = "(c.failure_window_started_at IS NULL"
            + " OR c.failure_window_started_at <= p.window_start"
            + " OR (c.locked_until IS NOT NULL AND c.locked_until <= p.now))";

    static final String INSERT_CREDENTIAL =
            "INSERT INTO credential_records (subject_id, login_identifier, password_hash, created_at, updated_at) "
            + "VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING";

    static final String INSERT_VERIFIED_CREDENTIAL =
            "INSERT INTO credential_records (subject_id, login_identifier, password_hash, email_verified, verified_at, created_at, updated_at) "
            + "VALUES ($1, $2, $3, TRUE, $4, $5, $6) ON CONFLICT DO NOTHING";

    static final String SELECT_BY_SUBJECT =
            "SELECT " + COLUMNS + " FROM credential_records WHERE subject_id = $1";

    static final String SELECT_BY_LOGIN =
            "SELECT " + COLUMNS + " FROM credential_records WHERE login_identifier = $1";

    static final String RESERVE_ATTEMPT =
            "UPDATE credential_records AS c SET "
            + "failed_login_attempts = CASE WHEN " + RESTART + " THEN 1 ELSE c.failed_login_attempts + 1 END, "
            + "failure_window_started_at = CASE WHEN " + RESTART + " THEN p.now ELSE c.failure_window_started_at END, "
            + "locked_until = CASE WHEN " + RESTART + " THEN NULL ELSE c.locked_until END, "
            + "updated_at = p.now "
            + "FROM (SELECT $1::timestamptz AS now, $2::timestamptz AS window_start, $3::int AS max_attempts) AS p "
            + "WHERE c.subject_id = $4 "
            + "AND (c.locked_until IS NULL OR c.locked_until <= p.now) "
            + "AND (" + RESTART + " OR c.failed_login_attempts < p.max_attempts)"
            + RETURNING_COLUMNS;

    static final String LOCK_IF_EXHAUSTED =
            "UPDATE credential_records AS c SET locked_until = p.lock_until, updated_at = p.now "
            + "FROM (SELECT $1::timestamptz AS lock_until, $2::timestamptz AS now, $3::int AS max_attempts) AS p "
            + "WHERE c.subject_id = $4 "
            + "AND c.failed_login_attempts >= p.max_attempts "
            + "AND (c.locked_until IS NULL OR c.locked_until <= p.now) "
            + "RETURNING c.locked_until";

    static final String CLEAR_FAILURES =
            "UPDATE credential_records SET failed_login_attempts = 0, failure_window_started_at = NULL, "
            + "locked_until = NULL, updated_at = $1 WHERE subject_id = $2";

    static final String REPLACE_HASH =
            "UPDATE credential_records SET password_hash = $1, updated_at = $2 "
            + "WHERE subject_id = $3 AND password_hash = $4";

    static final String CHANGE_PASSWORD =
            "UPDATE credential_records SET password_hash = $1, token_version = token_version + 1, "
            + "failed_login_attempts = 0, failure_window_started_at = NULL, locked_until = NULL, updated_at = $2 "
            + "WHERE subject_id = $3 AND password_hash = $4 RETURNING token_version";

    static final String LOCK_CREDENTIAL =
            "SELECT email_verified FROM credential_records WHERE subject_id = $1 FOR UPDATE";

    static final String RECENT_VERIFICATION_TOKEN =
            "SELECT 1 FROM account_verification_tokens WHERE subject_id = $1 AND created_at > $2 LIMIT 1";

    static final String SUPERSEDE_VERIFICATION_TOKENS =
            "UPDATE account_verification_tokens SET consumed_at = $1 WHERE subject_id = $2 AND consumed_at IS NULL";

    static final String INSERT_VERIFICATION_TOKEN =
            "INSERT INTO account_verification_tokens (id, subject_id, token_hash, expires_at, created_at) "
            + "VALUES ($1, $2, $3, $4, $5)";

    static final String CONSUME_VERIFICATION_TOKEN =
            "UPDATE account_verification_tokens SET consumed_at = $1 "
            + "WHERE token_hash = $2 AND consumed_at IS NULL AND expires_at > $3 RETURNING subject_id";

    static final String MARK_VERIFIED =
            "UPDATE credential_records SET email_verified = TRUE, verified_at = COALESCE(verified_at, $1), "
            + "updated_at = $2 WHERE subject_id = $3";

    static final String RECENT_RESET_TOKEN =
            "SELECT 1 FROM credential_reset_tokens WHERE subject_id = $1 AND created_at > $2 LIMIT 1";

    static final String SUPERSEDE_RESET_TOKENS =
            "UPDATE credential_reset_tokens SET consumed_at = $1 WHERE subject_id = $2 AND consumed_at IS NULL";

    static final String INSERT_RESET_TOKEN =
            "INSERT INTO credential_reset_tokens (id, subject_id, token_hash, expires_at, created_at) "
            + "VALUES ($1, $2, $3, $4, $5)";

    static final String SELECT_RESET_TOKEN =
            "SELECT id, subject_id, token_hash, expires_at, created_at, consumed_at "
            + "FROM credential_reset_tokens WHERE token_hash = $1";

    static final String CONSUME_RESET_TOKEN =
            "UPDATE credential_reset_tokens SET consumed_at = $1 "
            + "WHERE token_hash = $2 AND consumed_at IS NULL AND expires_at > $3 RETURNING subject_id";

    static final String RESET_PASSWORD =
            "UPDATE credential_records SET password_hash = $1, token_version = token_version + 1, "
            + "failed_login_attempts = 0, failure_window_started_at = NULL, locked_until = NULL, "
            + "email_verified = TRUE, verified_at = COALESCE(verified_at, $2), updated_at = $3 "
            + "WHERE subject_id = $4 RETURNING token_version";

    /** Every statement this repository issues. */
    static List<String> statements() {
        return List.of(INSERT_CREDENTIAL, INSERT_VERIFIED_CREDENTIAL, SELECT_BY_SUBJECT, SELECT_BY_LOGIN, RESERVE_ATTEMPT, LOCK_IF_EXHAUSTED,
                CLEAR_FAILURES, REPLACE_HASH, CHANGE_PASSWORD, LOCK_CREDENTIAL, RECENT_VERIFICATION_TOKEN,
                SUPERSEDE_VERIFICATION_TOKENS, INSERT_VERIFICATION_TOKEN, CONSUME_VERIFICATION_TOKEN,
                MARK_VERIFIED, RECENT_RESET_TOKEN, SUPERSEDE_RESET_TOKENS, INSERT_RESET_TOKEN, SELECT_RESET_TOKEN,
                CONSUME_RESET_TOKEN, RESET_PASSWORD);
    }

    private final TransactionalExecutor tx;

    public PostgresCredentialRepository(TransactionalExecutor tx) {
        this.tx = Objects.requireNonNull(tx, "tx must not be null");
    }

    @Override
    public boolean insertCredential(UUID subjectId, String loginIdentifier, String passwordHash, Instant now) {
        AtomicReference<Long> inserted = new AtomicReference<>(0L);
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(INSERT_CREDENTIAL)) {
                stmt.bindUuid(0, subjectId)
                    .bindString(1, loginIdentifier)
                    .bindString(2, passwordHash)
                    .bindInstant(3, now)
                    .bindInstant(4, now);
                inserted.set(stmt.executeUpdate());
            }
        });
        return inserted.get() == 1L;
    }

    @Override
    public boolean insertVerifiedCredential(UUID subjectId, String loginIdentifier, String passwordHash, Instant now) {
        AtomicReference<Long> inserted = new AtomicReference<>(0L);
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(INSERT_VERIFIED_CREDENTIAL)) {
                stmt.bindUuid(0, subjectId)
                    .bindString(1, loginIdentifier)
                    .bindString(2, passwordHash)
                    .bindInstant(3, now)
                    .bindInstant(4, now)
                    .bindInstant(5, now);
                inserted.set(stmt.executeUpdate());
            }
        });
        return inserted.get() == 1L;
    }

    @Override
    public Optional<CredentialRecord> findBySubject(UUID subjectId) {
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(SELECT_BY_SUBJECT)) {
                stmt.bindUuid(0, subjectId);
                return readCredential(stmt);
            }
        });
    }

    @Override
    public Optional<CredentialRecord> findByLoginIdentifier(String loginIdentifier) {
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(SELECT_BY_LOGIN)) {
                stmt.bindString(0, loginIdentifier);
                return readCredential(stmt);
            }
        });
    }

    @Override
    public Optional<CredentialRecord> reserveAttempt(UUID subjectId, LockoutPolicy policy, Instant now) {
        AtomicReference<Optional<CredentialRecord>> reserved = new AtomicReference<>(Optional.empty());
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(RESERVE_ATTEMPT)) {
                stmt.bindInstant(0, now)
                    .bindInstant(1, now.minus(policy.failureWindow()))
                    .bindInt(2, policy.maxAttempts())
                    .bindUuid(3, subjectId);
                reserved.set(readCredential(stmt));
            }
        });
        return reserved.get();
    }

    @Override
    public Optional<Instant> lockIfExhausted(UUID subjectId, LockoutPolicy policy, Instant now) {
        AtomicReference<Instant> lockedUntil = new AtomicReference<>();
        tx.executeManaged(conn -> {
            lockedUntil.set(null);
            try (PersistenceStatement stmt = conn.prepare(LOCK_IF_EXHAUSTED)) {
                stmt.bindInstant(0, now.plus(policy.lockoutDuration()))
                    .bindInstant(1, now)
                    .bindInt(2, policy.maxAttempts())
                    .bindUuid(3, subjectId);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        lockedUntil.set(rs.row().getInstant(0));
                    }
                }
            }
        });
        return Optional.ofNullable(lockedUntil.get());
    }

    @Override
    public void clearFailures(UUID subjectId, Instant now) {
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(CLEAR_FAILURES)) {
                stmt.bindInstant(0, now).bindUuid(1, subjectId);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public boolean replacePasswordHash(UUID subjectId, String expectedHash, String newHash, Instant now) {
        AtomicReference<Long> updated = new AtomicReference<>(0L);
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(REPLACE_HASH)) {
                stmt.bindString(0, newHash)
                    .bindInstant(1, now)
                    .bindUuid(2, subjectId)
                    .bindString(3, expectedHash);
                updated.set(stmt.executeUpdate());
            }
        });
        return updated.get() == 1L;
    }

    @Override
    public OptionalLong changePassword(UUID subjectId, String expectedHash, String newHash, Instant now) {
        AtomicReference<OptionalLong> version = new AtomicReference<>(OptionalLong.empty());
        tx.executeManaged(conn -> {
            version.set(OptionalLong.empty());
            try (PersistenceStatement stmt = conn.prepare(CHANGE_PASSWORD)) {
                stmt.bindString(0, newHash)
                    .bindInstant(1, now)
                    .bindUuid(2, subjectId)
                    .bindString(3, expectedHash);
                version.set(readLong(stmt));
            }
            if (version.get().isPresent()) {
                supersede(conn, SUPERSEDE_RESET_TOKENS, subjectId, now);
            }
        });
        return version.get();
    }

    @Override
    public boolean issueVerificationToken(UUID tokenId, UUID subjectId, String tokenHash, Instant expiresAt,
                                          Instant now, Instant cooldownStart) {
        AtomicReference<Boolean> issued = new AtomicReference<>(false);
        tx.executeManaged(conn -> {
            issued.set(false);
            Optional<Boolean> verified = lockCredential(conn, subjectId);
            if (verified.isEmpty() || verified.get() || recentToken(conn, RECENT_VERIFICATION_TOKEN, subjectId, cooldownStart)) {
                return;
            }
            supersede(conn, SUPERSEDE_VERIFICATION_TOKENS, subjectId, now);
            insertToken(conn, INSERT_VERIFICATION_TOKEN, tokenId, subjectId, tokenHash, expiresAt, now);
            issued.set(true);
        });
        return issued.get();
    }

    @Override
    public Optional<UUID> consumeVerificationToken(String tokenHash, Instant now) {
        AtomicReference<UUID> subject = new AtomicReference<>();
        tx.executeManaged(conn -> {
            subject.set(null);
            Optional<UUID> consumed = consumeToken(conn, CONSUME_VERIFICATION_TOKEN, tokenHash, now);
            if (consumed.isEmpty()) {
                return;
            }
            try (PersistenceStatement stmt = conn.prepare(MARK_VERIFIED)) {
                stmt.bindInstant(0, now).bindInstant(1, now).bindUuid(2, consumed.get());
                stmt.executeUpdate();
            }
            subject.set(consumed.get());
        });
        return Optional.ofNullable(subject.get());
    }

    @Override
    public boolean issueResetToken(UUID tokenId, UUID subjectId, String tokenHash, Instant expiresAt,
                                   Instant now, Instant cooldownStart) {
        AtomicReference<Boolean> issued = new AtomicReference<>(false);
        tx.executeManaged(conn -> {
            issued.set(false);
            if (lockCredential(conn, subjectId).isEmpty() || recentToken(conn, RECENT_RESET_TOKEN, subjectId, cooldownStart)) {
                return;
            }
            supersede(conn, SUPERSEDE_RESET_TOKENS, subjectId, now);
            insertToken(conn, INSERT_RESET_TOKEN, tokenId, subjectId, tokenHash, expiresAt, now);
            issued.set(true);
        });
        return issued.get();
    }

    @Override
    public Optional<TokenRecord> findResetToken(String tokenHash) {
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(SELECT_RESET_TOKEN)) {
                stmt.bindString(0, tokenHash);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (!rs.next()) {
                        return Optional.empty();
                    }
                    RowCursor row = rs.row();
                    return Optional.of(new TokenRecord(
                            row.getUuid(0), row.getUuid(1), row.getString(2),
                            row.getInstant(3), row.getInstant(4), row.getInstant(5)));
                }
            }
        });
    }

    @Override
    public OptionalLong consumeResetToken(String tokenHash, String newHash, Instant now) {
        AtomicReference<OptionalLong> version = new AtomicReference<>(OptionalLong.empty());
        tx.executeManaged(conn -> {
            version.set(OptionalLong.empty());
            Optional<UUID> subject = consumeToken(conn, CONSUME_RESET_TOKEN, tokenHash, now);
            if (subject.isEmpty()) {
                return;
            }
            try (PersistenceStatement stmt = conn.prepare(RESET_PASSWORD)) {
                stmt.bindString(0, newHash)
                    .bindInstant(1, now)
                    .bindInstant(2, now)
                    .bindUuid(3, subject.get());
                version.set(readLong(stmt));
            }
            supersede(conn, SUPERSEDE_RESET_TOKENS, subject.get(), now);
        });
        return version.get();
    }

    private static Optional<Boolean> lockCredential(PersistenceConnection conn, UUID subjectId) {
        try (PersistenceStatement stmt = conn.prepare(LOCK_CREDENTIAL)) {
            stmt.bindUuid(0, subjectId);
            try (QueryResult rs = stmt.executeQuery()) {
                return rs.next() ? Optional.of(rs.row().getBoolean(0)) : Optional.empty();
            }
        }
    }

    private static boolean recentToken(PersistenceConnection conn, String sql, UUID subjectId, Instant cooldownStart) {
        try (PersistenceStatement stmt = conn.prepare(sql)) {
            stmt.bindUuid(0, subjectId).bindInstant(1, cooldownStart);
            try (QueryResult rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    private static void supersede(PersistenceConnection conn, String sql, UUID subjectId, Instant now) {
        try (PersistenceStatement stmt = conn.prepare(sql)) {
            stmt.bindInstant(0, now).bindUuid(1, subjectId);
            stmt.executeUpdate();
        }
    }

    private static void insertToken(PersistenceConnection conn, String sql, UUID tokenId, UUID subjectId,
                                    String tokenHash, Instant expiresAt, Instant now) {
        try (PersistenceStatement stmt = conn.prepare(sql)) {
            stmt.bindUuid(0, tokenId)
                .bindUuid(1, subjectId)
                .bindString(2, tokenHash)
                .bindInstant(3, expiresAt)
                .bindInstant(4, now);
            stmt.executeUpdate();
        }
    }

    private static Optional<UUID> consumeToken(PersistenceConnection conn, String sql, String tokenHash, Instant now) {
        try (PersistenceStatement stmt = conn.prepare(sql)) {
            stmt.bindInstant(0, now).bindString(1, tokenHash).bindInstant(2, now);
            try (QueryResult rs = stmt.executeQuery()) {
                return rs.next() ? Optional.of(rs.row().getUuid(0)) : Optional.empty();
            }
        }
    }

    private static OptionalLong readLong(PersistenceStatement stmt) {
        try (QueryResult rs = stmt.executeQuery()) {
            return rs.next() ? OptionalLong.of(rs.row().getLong(0)) : OptionalLong.empty();
        }
    }

    private static Optional<CredentialRecord> readCredential(PersistenceStatement stmt) {
        try (QueryResult rs = stmt.executeQuery()) {
            if (!rs.next()) {
                return Optional.empty();
            }
            RowCursor row = rs.row();
            return Optional.of(new CredentialRecord(
                    row.getUuid(0),
                    row.getString(1),
                    row.getString(2),
                    row.getBoolean(3),
                    row.getInstant(4),
                    row.getInt(5),
                    row.getInstant(6),
                    row.getInstant(7),
                    row.getLong(8),
                    row.getInstant(9),
                    row.getInstant(10)));
        }
    }
}
