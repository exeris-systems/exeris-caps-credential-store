package eu.exeris.caps.credentialstore;

import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.credentialstore.api.AccountVerification;
import eu.exeris.caps.credentialstore.api.CredentialRecovery;
import eu.exeris.caps.credentialstore.api.CredentialStore;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.internal.DefaultAccountVerification;
import eu.exeris.caps.credentialstore.internal.DefaultCredentialRecovery;
import eu.exeris.caps.credentialstore.internal.DefaultCredentialStore;
import eu.exeris.caps.credentialstore.internal.audit.AuditTrailBridge;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRepository;
import eu.exeris.caps.credentialstore.internal.repository.InMemoryCredentialRepository;
import eu.exeris.caps.credentialstore.internal.repository.PostgresCredentialRepository;
import eu.exeris.caps.credentialstore.spi.InMemoryNotificationDispatcher;
import eu.exeris.caps.credentialstore.spi.InMemorySessionStore;
import eu.exeris.caps.credentialstore.spi.NotificationDispatcher;
import eu.exeris.caps.credentialstore.spi.SessionStore;
import eu.exeris.caps.credentialstore.internal.crypto.Pbkdf2PasswordEncoder;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder;
import eu.exeris.sdk.annotation.capability.CapabilityLifecycle;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;
import eu.exeris.sdk.annotation.capability.Requires;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Capability declaration and lifecycle owner for {@code exeris-caps-credential-store}.
 *
 * <p>Provides Layer 5 Domain Primitives:
 * <ul>
 *   <li>{@link CredentialStore} (password management, Argon2id verification, lockout policy)</li>
 *   <li>{@link AccountVerification} (single-use, hashed, expiring email-verification tokens)</li>
 *   <li>{@link CredentialRecovery} (forgot password and reset flow)</li>
 * </ul>
 *
 * @since 0.1.0
 */
@CapabilityModule
@CapabilityLifecycle
@Provides(service = CredentialStore.class, version = "1.0.0")
@Provides(service = AccountVerification.class, version = "1.0.0")
@Provides(service = CredentialRecovery.class, version = "1.0.0")
@Requires(service = NotificationDispatcher.class, versionRange = "[1.0.0,2.0.0)", optional = true)
@Requires(service = KernelPasswordEncoder.class, optional = true)
@Requires(service = TransactionalExecutor.class, optional = true)
@Requires(service = SessionStore.class, versionRange = "[1.0.0,2.0.0)", optional = true)
@Requires(service = AuditLogSink.class, versionRange = "[1.0.0,2.0.0)", optional = true)
public final class CredentialStoreModule implements CapabilityLifecycleHooks {

    private final CredentialStore credentialStore;
    private final AccountVerification accountVerification;
    private final CredentialRecovery credentialRecovery;

    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean ready = new AtomicBoolean(false);

    /**
     * Public no-arg constructor for reflective instantiation by the composition conductor.
     * Enforces fail-closed resolution of an Argon2id password encoder (ADR-099).
     */
    public CredentialStoreModule() {
        this(
                new InMemoryCredentialRepository(),
                resolvePasswordEncoderOrFail(),
                new KdfConcurrencyThrottler(),
                LockoutPolicy.defaults(),
                new InMemoryNotificationDispatcher(),
                new InMemorySessionStore(),
                null
        );
    }

    /**
     * Constructor wiring with a PostgreSQL {@link TransactionalExecutor}.
     */
    public CredentialStoreModule(
            TransactionalExecutor tx,
            KernelPasswordEncoder passwordEncoder,
            LockoutPolicy lockoutPolicy,
            NotificationDispatcher notificationDispatcher,
            SessionStore sessionStore,
            AuditLogSink auditLogSink
    ) {
        this(
                new PostgresCredentialRepository(tx),
                Objects.requireNonNull(passwordEncoder, "KernelPasswordEncoder must be explicitly provided (Argon2id). Silent PBKDF2 fallback is forbidden per ADR-099."),
                new KdfConcurrencyThrottler(),
                lockoutPolicy != null ? lockoutPolicy : LockoutPolicy.defaults(),
                notificationDispatcher != null ? notificationDispatcher : new InMemoryNotificationDispatcher(),
                sessionStore != null ? sessionStore : new InMemorySessionStore(),
                auditLogSink != null ? new AuditTrailBridge(auditLogSink) : null
        );
    }

    private static KernelPasswordEncoder resolvePasswordEncoderOrFail() {
        try {
            Class<?> argon2Class = Class.forName("eu.exeris.kernel.community.security.Argon2idPasswordEncoder");
            Class<?> configClass = Class.forName("eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig");
            Object defaultConfig = configClass.getMethod("defaults").invoke(null);
            return (KernelPasswordEncoder) argon2Class.getConstructor(configClass).newInstance(defaultConfig);
        } catch (Throwable ignored) {
        }
        throw new IllegalStateException("KernelPasswordEncoder (Argon2id) must be explicitly provided. Silent fallback to PBKDF2 is forbidden per ADR-099.");
    }

    /**
     * Constructor wiring with custom repository and dependencies.
     */
    public CredentialStoreModule(
            CredentialRepository repository,
            KernelPasswordEncoder passwordEncoder,
            KdfConcurrencyThrottler throttler,
            LockoutPolicy lockoutPolicy,
            NotificationDispatcher notificationDispatcher,
            SessionStore sessionStore,
            AuditTrailBridge auditTrail
    ) {
        Objects.requireNonNull(repository, "repository must not be null");
        Objects.requireNonNull(passwordEncoder, "passwordEncoder must not be null");
        Objects.requireNonNull(throttler, "throttler must not be null");
        Objects.requireNonNull(lockoutPolicy, "lockoutPolicy must not be null");
        Objects.requireNonNull(notificationDispatcher, "notificationDispatcher must not be null");

        this.credentialStore = new DefaultCredentialStore(
                repository,
                passwordEncoder,
                throttler,
                lockoutPolicy,
                sessionStore,
                auditTrail
        );
        this.accountVerification = new DefaultAccountVerification(
                repository,
                notificationDispatcher,
                auditTrail
        );
        this.credentialRecovery = new DefaultCredentialRecovery(
                repository,
                passwordEncoder,
                throttler,
                notificationDispatcher,
                sessionStore,
                auditTrail
        );
    }

    public CredentialStore credentialStore() {
        return credentialStore;
    }

    public AccountVerification accountVerification() {
        return accountVerification;
    }

    public CredentialRecovery credentialRecovery() {
        return credentialRecovery;
    }

    @Override
    public void initialize() throws Exception {
        initialized.set(true);
    }

    @Override
    public void ready() throws Exception {
        ready.set(true);
    }

    @Override
    public void drain(Duration remaining) throws Exception {
        ready.set(false);
    }

    @Override
    public void terminate() {
        ready.set(false);
        initialized.set(false);
    }

    public boolean isReady() {
        return ready.get();
    }

    public boolean isInitialized() {
        return initialized.get();
    }
}
