package eu.exeris.caps.credentialstore;

import eu.exeris.caps.credentialstore.api.AccountVerification;
import eu.exeris.caps.credentialstore.api.CredentialRecovery;
import eu.exeris.caps.credentialstore.api.CredentialStore;
import eu.exeris.caps.credentialstore.api.exception.CredentialAlreadyExistsException;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
import eu.exeris.caps.credentialstore.spi.InMemoryNotificationDispatcher;
import eu.exeris.caps.credentialstore.spi.InMemorySessionStore;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("CredentialStoreModule")
class CredentialStoreModuleTest {

    private static KernelPasswordEncoder encoder() {
        return new Argon2idPasswordEncoder(new PasswordEncoderConfig(8192, 1, 1, 16));
    }

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

        assertThatThrownBy(module::credentialStore).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(module::accountVerification).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(module::credentialRecovery).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("the public wiring constructor refuses a missing executor, encoder, dispatcher or policy")
    void publicWiringRefusesMissingDependencies() {
        InMemoryNotificationDispatcher dispatcher = new InMemoryNotificationDispatcher();
        KernelPasswordEncoder encoder = encoder();
        LockoutPolicy lockout = LockoutPolicy.defaults();
        TokenPolicy tokens = TokenPolicy.defaults();

        assertThatThrownBy(() -> new CredentialStoreModule(null, encoder, dispatcher, null, null, lockout, tokens, PasswordPolicy.defaults()))
                .isInstanceOf(NullPointerException.class).hasMessageContaining("tx");
        assertThatThrownBy(() -> wired(null, dispatcher, lockout, tokens))
                .isInstanceOf(NullPointerException.class).hasMessageContaining("passwordEncoder");
        assertThatThrownBy(() -> wired(encoder, null, lockout, tokens))
                .isInstanceOf(NullPointerException.class).hasMessageContaining("notificationDispatcher");
        assertThatThrownBy(() -> wired(encoder, dispatcher, null, tokens))
                .isInstanceOf(NullPointerException.class).hasMessageContaining("lockoutPolicy");
        assertThatThrownBy(() -> wired(encoder, dispatcher, lockout, null))
                .isInstanceOf(NullPointerException.class).hasMessageContaining("tokenPolicy");
    }

    @Test
    @DisplayName("the migrations it names are on the classpath")
    void migrationsArePackaged() {
        assertThat(CredentialStoreModule.MIGRATIONS).isNotEmpty().allSatisfy(path ->
                assertThat(CredentialStoreModule.class.getClassLoader().getResource(path)).as(path).isNotNull());
    }

    private static CredentialStoreModule wired(KernelPasswordEncoder encoder, InMemoryNotificationDispatcher dispatcher,
                                               LockoutPolicy lockout, TokenPolicy tokens) {
        return new CredentialStoreModule(new InMemoryCredentialRepository(), encoder, new KdfConcurrencyThrottler(),
                dispatcher, new InMemorySessionStore(), null, lockout, tokens, PasswordPolicy.defaults(), Clock.systemUTC());
    }

    @Test
    @DisplayName("register, verify, log in and reset through the module's services")
    void endToEndFlowUsingModuleServices() {
        InMemoryNotificationDispatcher dispatcher = new InMemoryNotificationDispatcher();
        CredentialStoreModule module = wired(encoder(), dispatcher, LockoutPolicy.defaults(), TokenPolicy.defaults());
        CredentialStore store = module.credentialStore();
        AccountVerification verification = module.accountVerification();
        CredentialRecovery recovery = module.credentialRecovery();

        UUID subjectId = UUID.randomUUID();
        char[] initialPassword = "InitialPassword123!".toCharArray();

        store.createCredential(subjectId, "user@exeris.eu", initialPassword);
        assertThat(store.authenticate("user@exeris.eu", initialPassword).isUnverified()).isTrue();
        UUID intruder = UUID.randomUUID();
        char[] takeoverPassword = "Takeover1!".toCharArray();
        assertThatThrownBy(() -> store.createCredential(intruder, "user@exeris.eu", takeoverPassword))
                .isInstanceOf(CredentialAlreadyExistsException.class);

        verification.issueVerification("user@exeris.eu");
        assertThat(verification.verifyAccount(dispatcher.dispatchedNotifications().get(0).rawToken())).isEqualTo(subjectId);
        assertThat(store.authenticate("user@exeris.eu", initialPassword).subjectId()).isEqualTo(subjectId);

        recovery.requestReset("user@exeris.eu");
        char[] newPassword = "BrandNewPassword456!".toCharArray();
        recovery.consumeReset(dispatcher.dispatchedNotifications().get(1).rawToken(), newPassword);

        assertThat(store.authenticate("user@exeris.eu", initialPassword).isInvalid()).isTrue();
        assertThat(store.authenticate("user@exeris.eu", newPassword).isSuccess()).isTrue();
        assertThat(store.getTokenVersion(subjectId)).hasValue(2);
    }
}
