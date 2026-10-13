package eu.exeris.caps.credentialstore;

import eu.exeris.caps.credentialstore.api.AccountVerification;
import eu.exeris.caps.credentialstore.api.CredentialRecovery;
import eu.exeris.caps.credentialstore.api.CredentialStore;
import eu.exeris.caps.credentialstore.api.model.CredentialVerificationResult;
import eu.exeris.caps.credentialstore.spi.InMemoryNotificationDispatcher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CredentialStoreModule Unit and Lifecycle Tests")
class CredentialStoreModuleTest {

    @Test
    @DisplayName("module lifecycle transitions through initialize, ready, drain, terminate")
    void lifecycleTransitions() throws Exception {
        CredentialStoreModule module = new CredentialStoreModule();

        assertThat(module.isInitialized()).isFalse();
        assertThat(module.isReady()).isFalse();

        module.initialize();
        assertThat(module.isInitialized()).isTrue();
        assertThat(module.isReady()).isFalse();

        module.ready();
        assertThat(module.isReady()).isTrue();

        module.drain(Duration.ofSeconds(5));
        assertThat(module.isReady()).isFalse();

        module.terminate();
        assertThat(module.isInitialized()).isFalse();
        assertThat(module.isReady()).isFalse();
    }

    @Test
    @DisplayName("the conductor's no-arg instance hands out no service")
    void noArgInstanceIsLifecycleOnly() {
        CredentialStoreModule module = new CredentialStoreModule();

        org.assertj.core.api.Assertions.assertThatThrownBy(module::credentialStore)
                .isInstanceOf(IllegalStateException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(module::accountVerification)
                .isInstanceOf(IllegalStateException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(module::credentialRecovery)
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("the public wiring constructor refuses a missing executor, encoder or dispatcher")
    void publicWiringRefusesMissingDependencies() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new CredentialStoreModule(
                null, encoder(), eu.exeris.caps.credentialstore.api.model.LockoutPolicy.defaults(),
                new InMemoryNotificationDispatcher(), null, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("tx");
    }

    private static eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder encoder() {
        return new eu.exeris.kernel.community.security.Argon2idPasswordEncoder(
                new eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig(8192, 1, 1, 16));
    }

    @Test
    @DisplayName("rejects null password encoder fail-closed per ADR-099")
    void failClosedWithoutPasswordEncoder() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new CredentialStoreModule(
                new eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository(),
                null,
                new eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler(),
                eu.exeris.caps.credentialstore.api.model.LockoutPolicy.defaults(),
                new InMemoryNotificationDispatcher(),
                new eu.exeris.caps.credentialstore.spi.InMemorySessionStore(),
                null
        )).isInstanceOf(NullPointerException.class)
          .hasMessageContaining("passwordEncoder must not be null");
    }

    @Test
    @DisplayName("end-to-end integration flow using module provided services")
    void endToEndFlowUsingModuleServices() {
        InMemoryNotificationDispatcher dispatcher = new InMemoryNotificationDispatcher();
        CredentialStoreModule module = new CredentialStoreModule(
                new eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository(),
                new eu.exeris.kernel.community.security.Argon2idPasswordEncoder(
                        new eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig(8192, 1, 1, 16)
                ),
                new eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler(),
                eu.exeris.caps.credentialstore.api.model.LockoutPolicy.defaults(),
                dispatcher,
                new eu.exeris.caps.credentialstore.spi.InMemorySessionStore(),
                null
        );

        CredentialStore store = module.credentialStore();
        AccountVerification verification = module.accountVerification();
        CredentialRecovery recovery = module.credentialRecovery();

        UUID subjectId = UUID.randomUUID();
        char[] initialPassword = "InitialPassword123!".toCharArray();

        // 1. Set Credential
        store.setCredential(subjectId, initialPassword);
        assertThat(store.isVerified(subjectId)).isFalse();

        // 2. Issue Verification & Verify Account
        verification.issueVerification(subjectId, "user@exeris.eu");
        String verifyToken = dispatcher.dispatchedNotifications().get(0).rawToken();
        UUID verifiedSubject = verification.verifyAccount(verifyToken);
        assertThat(verifiedSubject).isEqualTo(subjectId);
        assertThat(store.isVerified(subjectId)).isTrue();

        // 3. Verify Credential
        CredentialVerificationResult authResult = store.verifyCredential(subjectId, initialPassword);
        assertThat(authResult.isSuccess()).isTrue();

        // 4. Request Password Reset & Consume Reset
        recovery.requestReset(subjectId, "user@exeris.eu");
        String resetToken = dispatcher.dispatchedNotifications().get(1).rawToken();
        char[] newPassword = "BrandNewPassword456!".toCharArray();
        recovery.consumeReset(resetToken, newPassword);

        // 5. Verify Old Password Fails, New Password Succeeds
        assertThat(store.verifyCredential(subjectId, initialPassword).isInvalid()).isTrue();
        assertThat(store.verifyCredential(subjectId, newPassword).isSuccess()).isTrue();
        assertThat(store.getTokenVersion(subjectId)).isEqualTo(2L);
    }
}
