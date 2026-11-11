package eu.exeris.caps.credentialstore.internal.repository;

import eu.exeris.caps.credentialstore.api.CredentialProvisioning;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
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
}
