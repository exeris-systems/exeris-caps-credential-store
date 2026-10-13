package eu.exeris.caps.credentialstore.internal.repository;

import eu.exeris.kernel.community.persistence.jdbc.JdbcPersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("PostgresCredentialRepository Live PostgreSQL Integration Tests")
class PostgresCredentialRepositoryLiveIT {

    private static final String PG_URL = "jdbc:postgresql://localhost:5432/exeris_showroom";
    private static final String PG_USER = "exeris";
    private static final String PG_PASS = "exeris_password";
    private static final String TEST_SCHEMA = "test_cred_store_live";

    private static Connection jdbcConn;
    private static PostgresCredentialRepository repository;

    @BeforeAll
    static void setUpDatabase() {
        try (Connection initConn = DriverManager.getConnection(PG_URL, PG_USER, PG_PASS);
             Statement stmt = initConn.createStatement()) {
            stmt.execute("DROP SCHEMA IF EXISTS " + TEST_SCHEMA + " CASCADE");
            stmt.execute("CREATE SCHEMA " + TEST_SCHEMA);
        } catch (SQLException e) {
            Assumptions.abort("PostgreSQL not reachable at " + PG_URL + ": " + e.getMessage());
            return;
        }

        try {
            jdbcConn = DriverManager.getConnection(PG_URL + "?currentSchema=" + TEST_SCHEMA, PG_USER, PG_PASS);
            try (Statement stmt = jdbcConn.createStatement()) {
                // Execute DDL schema
                try (InputStream is = PostgresCredentialRepositoryLiveIT.class.getResourceAsStream("/schema/credential-store-schema.sql")) {
                    if (is != null) {
                        String ddl = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                        String cleanDdl = ddl.replaceAll("(?m)^--.*$", "");
                        for (String command : cleanDdl.split(";")) {
                            String trimmed = command.trim();
                            if (!trimmed.isEmpty()) {
                                stmt.execute(trimmed);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Assumptions.abort("Failed to initialize test schema on PostgreSQL: " + e.getMessage());
            return;
        }

        TransactionalExecutor tx = new TransactionalExecutor() {
            @Override
            public void execute(TransactionalWork work) {
                executeManaged(work);
            }

            @Override
            public void executeManaged(TransactionalWork work) {
                try {
                    PersistenceConnection conn = new JdbcPersistenceConnection(jdbcConn);
                    conn.beginTransaction();
                    work.run(conn);
                    conn.commit();
                } catch (Exception e) {
                    try {
                        jdbcConn.rollback();
                    } catch (SQLException ignored) {}
                    throw new RuntimeException(e);
                }
            }

            @Override
            public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
                executeManaged(work);
            }

            @Override
            public <T> T query(Function<PersistenceConnection, T> query) {
                try {
                    PersistenceConnection conn = new JdbcPersistenceConnection(jdbcConn);
                    return query.apply(conn);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        repository = new PostgresCredentialRepository(tx);
    }

    @AfterAll
    static void tearDownDatabase() {
        if (jdbcConn != null) {
            try (Statement stmt = jdbcConn.createStatement()) {
                stmt.execute("DROP SCHEMA IF EXISTS " + TEST_SCHEMA + " CASCADE");
            } catch (SQLException ignored) {
            } finally {
                try {
                    jdbcConn.close();
                } catch (SQLException ignored) {}
            }
        }
    }

    @Test
    @DisplayName("credential lifecycle: save, find, recordFailed, unlock, updatePassword, getTokenVersion, emailVerified")
    void credentialLifecycleLivePostgres() {
        UUID subjectId = UUID.randomUUID();
        String passwordHash = "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$c29tZWhhc2g";
        Instant now = Instant.now();

        // 1. Save credential
        repository.saveCredential(subjectId, passwordHash, now);

        // 2. Find credential
        Optional<CredentialRecord> opt = repository.findCredential(subjectId);
        assertThat(opt).isPresent();
        CredentialRecord record = opt.get();
        assertThat(record.subjectId()).isEqualTo(subjectId);
        assertThat(record.passwordHash()).isEqualTo(passwordHash);
        assertThat(record.emailVerified()).isFalse();
        assertThat(record.verifiedAt()).isNull();
        assertThat(record.failedLoginAttempts()).isZero();
        assertThat(record.lockedUntil()).isNull();
        assertThat(record.tokenVersion()).isEqualTo(1L);

        // 3. Record failed login
        Instant lockedUntil = now.plusSeconds(900);
        repository.recordFailedLogin(subjectId, 5, lockedUntil, now);
        CredentialRecord locked = repository.findCredential(subjectId).orElseThrow();
        assertThat(locked.failedLoginAttempts()).isEqualTo(5);
        assertThat(locked.lockedUntil()).isNotNull();

        // 4. Unlock account
        repository.unlockAccount(subjectId, now);
        CredentialRecord unlocked = repository.findCredential(subjectId).orElseThrow();
        assertThat(unlocked.failedLoginAttempts()).isZero();
        assertThat(unlocked.lockedUntil()).isNull();

        // 5. Update password
        String newHash = "$argon2id$v=19$m=65536,t=3,p=1$bmV3c2FsdA$bmV3aGFzaA";
        repository.updatePassword(subjectId, newHash, 2L, now);
        CredentialRecord updated = repository.findCredential(subjectId).orElseThrow();
        assertThat(updated.passwordHash()).isEqualTo(newHash);
        assertThat(updated.tokenVersion()).isEqualTo(2L);
        assertThat(repository.getTokenVersion(subjectId)).isEqualTo(2L);

        // 6. Verify email
        assertThat(repository.isEmailVerified(subjectId)).isFalse();
        repository.setEmailVerified(subjectId, now);
        assertThat(repository.isEmailVerified(subjectId)).isTrue();
    }

    @Test
    @DisplayName("verification token lifecycle and double-spend protection on live Postgres")
    void verificationTokenLifecycleLivePostgres() {
        UUID tokenId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        String tokenHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(86400);

        repository.saveVerificationToken(tokenId, subjectId, tokenHash, expiresAt, now);

        Optional<TokenRecord> found = repository.findVerificationTokenByHash(tokenHash);
        assertThat(found).isPresent();
        assertThat(found.get().id()).isEqualTo(tokenId);
        assertThat(found.get().subjectId()).isEqualTo(subjectId);
        assertThat(found.get().consumedAt()).isNull();

        Optional<TokenRecord> latest = repository.findLatestVerificationToken(subjectId);
        assertThat(latest).isPresent();
        assertThat(latest.get().id()).isEqualTo(tokenId);

        // First consume succeeds
        boolean firstConsume = repository.consumeVerificationToken(tokenId, now);
        assertThat(firstConsume).isTrue();

        // Double-spend consume fails
        boolean secondConsume = repository.consumeVerificationToken(tokenId, now);
        assertThat(secondConsume).isFalse();
    }

    @Test
    @DisplayName("reset token lifecycle and double-spend protection on live Postgres")
    void resetTokenLifecycleLivePostgres() {
        UUID tokenId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        String tokenHash = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(900);

        repository.saveResetToken(tokenId, subjectId, tokenHash, expiresAt, now);

        Optional<TokenRecord> found = repository.findResetTokenByHash(tokenHash);
        assertThat(found).isPresent();
        assertThat(found.get().id()).isEqualTo(tokenId);
        assertThat(found.get().consumedAt()).isNull();

        Optional<TokenRecord> latest = repository.findLatestResetToken(subjectId);
        assertThat(latest).isPresent();
        assertThat(latest.get().id()).isEqualTo(tokenId);

        // First consume succeeds
        boolean firstConsume = repository.consumeResetToken(tokenId, now);
        assertThat(firstConsume).isTrue();

        // Double-spend consume fails
        boolean secondConsume = repository.consumeResetToken(tokenId, now);
        assertThat(secondConsume).isFalse();
    }
}
