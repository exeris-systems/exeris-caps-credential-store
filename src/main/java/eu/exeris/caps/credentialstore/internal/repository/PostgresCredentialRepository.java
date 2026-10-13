package eu.exeris.caps.credentialstore.internal.repository;

import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * PostgreSQL implementation of {@link CredentialRepository} using {@link TransactionalExecutor}
 * and {@code exeris-kernel-spi} persistence contracts.
 */
public final class PostgresCredentialRepository implements CredentialRepository {

    private final TransactionalExecutor tx;

    public PostgresCredentialRepository(TransactionalExecutor tx) {
        this.tx = Objects.requireNonNull(tx, "tx must not be null");
    }

    @Override
    public void saveCredential(UUID subjectId, String passwordHash, Instant now) {
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "INSERT INTO credential_records (subject_id, password_hash, email_verified, failed_login_attempts, token_version, created_at, updated_at) " +
                    "VALUES ($1, $2, FALSE, 0, 1, $3, $4) " +
                    "ON CONFLICT (subject_id) DO UPDATE SET " +
                    "password_hash = EXCLUDED.password_hash, " +
                    "updated_at = EXCLUDED.updated_at")) {
                stmt.bindUuid(0, subjectId)
                    .bindString(1, passwordHash)
                    .bindInstant(2, now)
                    .bindInstant(3, now);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public Optional<CredentialRecord> findCredential(UUID subjectId) {
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT subject_id, password_hash, email_verified, verified_at, failed_login_attempts, locked_until, token_version, created_at, updated_at " +
                    "FROM credential_records WHERE subject_id = $1")) {
                stmt.bindUuid(0, subjectId);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        return Optional.of(new CredentialRecord(
                                row.getUuid(0),
                                row.getString(1),
                                row.getBoolean(2),
                                row.getInstant(3),
                                row.getInt(4),
                                row.getInstant(5),
                                row.getLong(6),
                                row.getInstant(7),
                                row.getInstant(8)
                        ));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public void updatePassword(UUID subjectId, String newPasswordHash, long newTokenVersion, Instant now) {
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE credential_records " +
                    "SET password_hash = $1, token_version = $2, failed_login_attempts = 0, locked_until = NULL, updated_at = $3 " +
                    "WHERE subject_id = $4")) {
                stmt.bindString(0, newPasswordHash)
                    .bindLong(1, newTokenVersion)
                    .bindInstant(2, now)
                    .bindUuid(3, subjectId);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public void recordFailedLogin(UUID subjectId, int failedAttempts, Instant lockedUntil, Instant now) {
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE credential_records " +
                    "SET failed_login_attempts = $1, locked_until = $2, updated_at = $3 " +
                    "WHERE subject_id = $4")) {
                stmt.bindInt(0, failedAttempts);
                if (lockedUntil != null) {
                    stmt.bindInstant(1, lockedUntil);
                } else {
                    stmt.bindNull(1);
                }
                stmt.bindInstant(2, now)
                    .bindUuid(3, subjectId);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public void resetFailedLogins(UUID subjectId, Instant now) {
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE credential_records " +
                    "SET failed_login_attempts = 0, updated_at = $1 " +
                    "WHERE subject_id = $2")) {
                stmt.bindInstant(0, now)
                    .bindUuid(1, subjectId);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public void unlockAccount(UUID subjectId, Instant now) {
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE credential_records " +
                    "SET failed_login_attempts = 0, locked_until = NULL, updated_at = $1 " +
                    "WHERE subject_id = $2")) {
                stmt.bindInstant(0, now)
                    .bindUuid(1, subjectId);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public long getTokenVersion(UUID subjectId) {
        Long version = tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT token_version FROM credential_records WHERE subject_id = $1")) {
                stmt.bindUuid(0, subjectId);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return rs.row().getLong(0);
                    }
                    return 1L;
                }
            }
        });
        return version != null ? version : 1L;
    }

    @Override
    public boolean isEmailVerified(UUID subjectId) {
        Boolean verified = tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT email_verified FROM credential_records WHERE subject_id = $1")) {
                stmt.bindUuid(0, subjectId);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return rs.row().getBoolean(0);
                    }
                    return false;
                }
            }
        });
        return verified != null && verified;
    }

    @Override
    public void setEmailVerified(UUID subjectId, Instant now) {
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE credential_records " +
                    "SET email_verified = TRUE, verified_at = $1, updated_at = $2 " +
                    "WHERE subject_id = $3")) {
                stmt.bindInstant(0, now)
                    .bindInstant(1, now)
                    .bindUuid(2, subjectId);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public void saveVerificationToken(UUID id, UUID subjectId, String tokenHash, Instant expiresAt, Instant now) {
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "INSERT INTO account_verification_tokens (id, subject_id, token_hash, expires_at, created_at) " +
                    "VALUES ($1, $2, $3, $4, $5)")) {
                stmt.bindUuid(0, id)
                    .bindUuid(1, subjectId)
                    .bindString(2, tokenHash)
                    .bindInstant(3, expiresAt)
                    .bindInstant(4, now);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public Optional<TokenRecord> findLatestVerificationToken(UUID subjectId) {
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, subject_id, token_hash, expires_at, created_at, consumed_at " +
                    "FROM account_verification_tokens " +
                    "WHERE subject_id = $1 " +
                    "ORDER BY created_at DESC " +
                    "LIMIT 1")) {
                stmt.bindUuid(0, subjectId);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        return Optional.of(new TokenRecord(
                                row.getUuid(0),
                                row.getUuid(1),
                                row.getString(2),
                                row.getInstant(3),
                                row.getInstant(4),
                                row.getInstant(5)
                        ));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public Optional<TokenRecord> findVerificationTokenByHash(String tokenHash) {
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, subject_id, token_hash, expires_at, created_at, consumed_at " +
                    "FROM account_verification_tokens " +
                    "WHERE token_hash = $1")) {
                stmt.bindString(0, tokenHash);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        return Optional.of(new TokenRecord(
                                row.getUuid(0),
                                row.getUuid(1),
                                row.getString(2),
                                row.getInstant(3),
                                row.getInstant(4),
                                row.getInstant(5)
                        ));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public boolean consumeVerificationToken(UUID tokenId, Instant now) {
        Long affected = tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE account_verification_tokens " +
                    "SET consumed_at = $1 " +
                    "WHERE id = $2 AND consumed_at IS NULL")) {
                stmt.bindInstant(0, now)
                    .bindUuid(1, tokenId);
                return stmt.executeUpdate();
            }
        });
        return affected != null && affected > 0;
    }

    @Override
    public void saveResetToken(UUID id, UUID subjectId, String tokenHash, Instant expiresAt, Instant now) {
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "INSERT INTO credential_reset_tokens (id, subject_id, token_hash, expires_at, created_at) " +
                    "VALUES ($1, $2, $3, $4, $5)")) {
                stmt.bindUuid(0, id)
                    .bindUuid(1, subjectId)
                    .bindString(2, tokenHash)
                    .bindInstant(3, expiresAt)
                    .bindInstant(4, now);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public Optional<TokenRecord> findLatestResetToken(UUID subjectId) {
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, subject_id, token_hash, expires_at, created_at, consumed_at " +
                    "FROM credential_reset_tokens " +
                    "WHERE subject_id = $1 " +
                    "ORDER BY created_at DESC " +
                    "LIMIT 1")) {
                stmt.bindUuid(0, subjectId);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        return Optional.of(new TokenRecord(
                                row.getUuid(0),
                                row.getUuid(1),
                                row.getString(2),
                                row.getInstant(3),
                                row.getInstant(4),
                                row.getInstant(5)
                        ));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public Optional<TokenRecord> findResetTokenByHash(String tokenHash) {
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, subject_id, token_hash, expires_at, created_at, consumed_at " +
                    "FROM credential_reset_tokens " +
                    "WHERE token_hash = $1")) {
                stmt.bindString(0, tokenHash);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        return Optional.of(new TokenRecord(
                                row.getUuid(0),
                                row.getUuid(1),
                                row.getString(2),
                                row.getInstant(3),
                                row.getInstant(4),
                                row.getInstant(5)
                        ));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public boolean consumeResetToken(UUID tokenId, Instant now) {
        Long affected = tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE credential_reset_tokens " +
                    "SET consumed_at = $1 " +
                    "WHERE id = $2 AND consumed_at IS NULL")) {
                stmt.bindInstant(0, now)
                    .bindUuid(1, tokenId);
                return stmt.executeUpdate();
            }
        });
        return affected != null && affected > 0;
    }
}
