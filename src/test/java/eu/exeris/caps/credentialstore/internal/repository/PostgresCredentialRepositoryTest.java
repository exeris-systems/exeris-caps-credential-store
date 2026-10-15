package eu.exeris.caps.credentialstore.internal.repository;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Structural properties of the statements, checked without a database; their behaviour is covered by
 * {@link PostgresCredentialRepositoryLiveIT}.
 */
@DisplayName("PostgresCredentialRepository statements")
class PostgresCredentialRepositoryTest {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\$(\\d+)");

    @Test
    @DisplayName("each placeholder appears once, in ascending order from $1, as positional binding requires")
    void placeholdersArePositional() {
        for (String sql : PostgresCredentialRepository.statements()) {
            List<Integer> seen = new ArrayList<>();
            Matcher m = PLACEHOLDER.matcher(sql);
            while (m.find()) {
                seen.add(Integer.parseInt(m.group(1)));
            }
            List<Integer> expected = new ArrayList<>();
            for (int i = 1; i <= seen.size(); i++) {
                expected.add(i);
            }
            assertThat(seen).as(sql).isEqualTo(expected);
        }
    }

    @Test
    @DisplayName("no statement can overwrite an existing credential on insert")
    void noUpsert() {
        for (String sql : PostgresCredentialRepository.statements()) {
            assertThat(sql.toUpperCase(Locale.ROOT)).as(sql).doesNotContain("DO UPDATE");
        }
        assertThat(PostgresCredentialRepository.INSERT_CREDENTIAL).endsWith("ON CONFLICT DO NOTHING");
    }

    @Test
    @DisplayName("every password write is guarded by the expected hash or by a consumed token")
    void passwordWritesAreGuarded() {
        assertThat(PostgresCredentialRepository.CHANGE_PASSWORD).contains("AND password_hash = $4");
        assertThat(PostgresCredentialRepository.REPLACE_HASH).contains("AND password_hash = $4");
        assertThat(PostgresCredentialRepository.CONSUME_RESET_TOKEN)
                .contains("consumed_at IS NULL").contains("expires_at > $3").contains("RETURNING subject_id");
        assertThat(PostgresCredentialRepository.statements().stream()
                .filter(sql -> sql.contains("SET password_hash"))
                .toList())
                .containsExactlyInAnyOrder(PostgresCredentialRepository.CHANGE_PASSWORD,
                        PostgresCredentialRepository.REPLACE_HASH, PostgresCredentialRepository.RESET_PASSWORD);
    }
}
