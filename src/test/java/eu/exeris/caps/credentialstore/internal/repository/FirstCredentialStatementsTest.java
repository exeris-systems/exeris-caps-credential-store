package eu.exeris.caps.credentialstore.internal.repository;

import eu.exeris.caps.credentialstore.api.CredentialProvisioning;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.internal.CountingPasswordEncoder;
import eu.exeris.caps.credentialstore.internal.DefaultCredentialProvisioning;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.util.ArrayList;
import java.util.UUID;
import java.util.function.Function;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Structural guarantees of the first-credential provisioning, checked without a database. */
@DisplayName("First-credential provisioning: statements and contract")
class FirstCredentialStatementsTest {

    /** SHA-256 prefixes of the statements that existed before first-credential provisioning was added. */
    private static final Map<String, String> EXISTING = Map.ofEntries(
            Map.entry("CHANGE_PASSWORD", "af6ff8d947d604e8"),
            Map.entry("CLEAR_FAILURES", "750fbe51122a9322"),
            Map.entry("CONSUME_RESET_TOKEN", "a842fd6110b4b311"),
            Map.entry("CONSUME_VERIFICATION_TOKEN", "b358e3a262dee587"),
            Map.entry("INSERT_CREDENTIAL", "025ac8cec5434cde"),
            Map.entry("INSERT_RESET_TOKEN", "f17dab244c45f648"),
            Map.entry("INSERT_VERIFICATION_TOKEN", "9b154f924069e8e1"),
            Map.entry("INSERT_VERIFIED_CREDENTIAL", "0e28b07370a34c18"),
            Map.entry("LOCK_CREDENTIAL", "7af86ae1d931d8fa"),
            Map.entry("LOCK_IF_EXHAUSTED", "8a497f9c5e77a4ee"),
            Map.entry("MARK_VERIFIED", "2741e112f15f2bfa"),
            Map.entry("RECENT_RESET_TOKEN", "818b9d420c4e4c81"),
            Map.entry("RECENT_VERIFICATION_TOKEN", "a8af9aaf504b0a7e"),
            Map.entry("REPLACE_HASH", "6c7bcb464aed4358"),
            Map.entry("RESERVE_ATTEMPT", "42ed5e175a980c34"),
            Map.entry("RESET_PASSWORD", "4bc9f8441775a97b"),
            Map.entry("SELECT_BY_LOGIN", "d86fdd1ef91393b5"),
            Map.entry("SELECT_BY_SUBJECT", "d427d7dbf4675c57"),
            Map.entry("SELECT_RESET_TOKEN", "61df9c7672c5a04d"),
            Map.entry("SUPERSEDE_RESET_TOKENS", "f64ff119cd0b9350"),
            Map.entry("SUPERSEDE_VERIFICATION_TOKENS", "a5792072bfb0c7d0"));

    private static String digest(String sql) throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(sql.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(h).substring(0, 16);
    }

    @Test
    @DisplayName("every pre-existing statement is byte-identical")
    void existingStatementsUnchanged() throws Exception {
        Map<String, String> actual = new HashMap<>();
        for (var field : PostgresCredentialRepository.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class
                    && !Modifier.isPrivate(field.getModifiers()) && EXISTING.containsKey(field.getName())) {
                field.setAccessible(true);
                actual.put(field.getName(), digest((String) field.get(null)));
            }
        }
        assertThat(actual).isEqualTo(EXISTING);
    }

    @Test
    @DisplayName("the new statements carry no placeholder, no upsert and write nothing themselves")
    void newStatementsAreReadsAndALock() {
        List<String> added = List.of(PostgresCredentialRepository.RLS_STATE,
                PostgresCredentialRepository.LOCK_FOR_FIRST, PostgresCredentialRepository.ANY_CREDENTIAL);
        assertThat(PostgresCredentialRepository.statements()).containsAll(added);
        for (String sql : added) {
            String upper = sql.toUpperCase(Locale.ROOT);
            assertThat(sql).doesNotContain("$");
            assertThat(upper).doesNotContain("DO UPDATE", "SET PASSWORD_HASH", "INSERT", "DELETE", "UPDATE ");
        }
        assertThat(PostgresCredentialRepository.statements()).doesNotHaveDuplicates();
    }

    @Test
    @DisplayName("the lock conflicts with itself and with row writers but not with plain reads")
    void lockModeExcludesWritersNotReaders() {
        String lock = PostgresCredentialRepository.LOCK_FOR_FIRST.toUpperCase(Locale.ROOT);
        assertThat(lock).contains("LOCK TABLE CREDENTIAL_RECORDS").contains("SHARE ROW EXCLUSIVE");
        assertThat(lock).doesNotContain("ACCESS EXCLUSIVE").doesNotContain("EXCLUSIVE MODE NOWAIT");
    }

    @Test
    @DisplayName("the operation is a public, additive method outside internal packages; versions stay 0.1.0")
    void publicSurface() throws Exception {
        Method m = CredentialProvisioning.class.getMethod("provisionFirstVerified",
                java.util.UUID.class, String.class, char[].class);
        assertThat(Modifier.isPublic(m.getModifiers())).isTrue();
        assertThat(m.getReturnType()).isEqualTo(java.util.Optional.class);
        assertThat(CredentialProvisioning.class.getPackageName()).doesNotContain("internal");
        assertThat(CredentialProvisioning.class.getMethods()).extracting(Method::getName)
                .contains("provisionVerified", "provisionFirstVerified");
        String source = java.nio.file.Files.readString(java.nio.file.Path.of(
                "src/main/java/eu/exeris/caps/credentialstore/CredentialStoreModule.java"));
        var provides = java.util.regex.Pattern.compile("@Provides\\(service = (\\w+)\\.class, version = \"([^\"]+)\"\\)")
                .matcher(source);
        List<String> declared = new java.util.ArrayList<>();
        while (provides.find()) {
            declared.add(provides.group(1) + "@" + provides.group(2));
        }
        assertThat(declared).containsExactlyInAnyOrder("CredentialStore@0.1.0", "AccountVerification@0.1.0",
                "CredentialRecovery@0.1.0", "CredentialProvisioning@0.1.0");
    }

    @Test
    @DisplayName("the first statement the unit executes is the table lock; the insert comes last")
    void lockIsTheFirstStatementOfTheUnit() {
        List<String> executed = new ArrayList<>();
        TransactionalExecutor recording = new TransactionalExecutor() {
            @Override
            public void execute(TransactionalWork work) {
                executeManaged(work);
            }

            @Override
            public void executeManaged(TransactionalWork work) {
                work.run(recordingConnection(executed));
            }

            @Override
            public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
                executeManaged(work);
            }

            @Override
            public <T> T query(Function<PersistenceConnection, T> query) {
                return query.apply(recordingConnection(executed));
            }
        };
        DefaultCredentialProvisioning provisioning = new DefaultCredentialProvisioning(
                new PostgresCredentialRepository(recording),
                new PasswordHashing(new CountingPasswordEncoder(), new KdfConcurrencyThrottler(1)),
                PasswordPolicy.defaults(), null, Clock.systemUTC());

        provisioning.provisionFirstVerified(UUID.randomUUID(), "first@exeris.eu", "a-Long-Enough-Pw-1234".toCharArray());

        assertThat(executed).containsExactly(PostgresCredentialRepository.LOCK_FOR_FIRST,
                PostgresCredentialRepository.RLS_STATE, PostgresCredentialRepository.ANY_CREDENTIAL,
                PostgresCredentialRepository.INSERT_VERIFIED_CREDENTIAL);
    }

    /** A connection whose statements record their SQL and report no rows, one row affected. */
    private static PersistenceConnection recordingConnection(List<String> executed) {
        QueryResult empty = (QueryResult) Proxy.newProxyInstance(QueryResult.class.getClassLoader(),
                new Class<?>[] {QueryResult.class}, (proxy, method, args) -> defaultFor(method.getReturnType()));
        return (PersistenceConnection) Proxy.newProxyInstance(PersistenceConnection.class.getClassLoader(),
                new Class<?>[] {PersistenceConnection.class}, (proxy, method, args) -> {
                    if (!method.getName().equals("prepare")) {
                        return defaultFor(method.getReturnType());
                    }
                    executed.add((String) args[0]);
                    return Proxy.newProxyInstance(PersistenceStatement.class.getClassLoader(),
                            new Class<?>[] {PersistenceStatement.class}, (statement, m, a) -> {
                                if (m.getReturnType() == PersistenceStatement.class) {
                                    return statement;
                                }
                                if (m.getReturnType() == QueryResult.class) {
                                    return empty;
                                }
                                return m.getName().equals("executeUpdate") ? Long.valueOf(1L)
                                        : defaultFor(m.getReturnType());
                            });
                });
    }

    private static Object defaultFor(Class<?> type) {
        if (type == boolean.class) {
            return false;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == int.class) {
            return 0;
        }
        return null;
    }
}
