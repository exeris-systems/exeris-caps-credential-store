package eu.exeris.caps.credentialstore;

import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.credentialstore.api.AccountVerification;
import eu.exeris.caps.credentialstore.api.CredentialRecovery;
import eu.exeris.caps.credentialstore.api.CredentialStore;
import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.credentialstore.internal.DefaultAccountVerification;
import eu.exeris.caps.credentialstore.internal.DefaultCredentialRecovery;
import eu.exeris.caps.credentialstore.internal.DefaultCredentialStore;
import eu.exeris.caps.credentialstore.internal.audit.AuditTrailBridge;
import eu.exeris.caps.credentialstore.internal.crypto.KdfConcurrencyThrottler;
import eu.exeris.caps.credentialstore.internal.crypto.PasswordHashing;
import eu.exeris.caps.credentialstore.internal.repository.CredentialRepository;
import eu.exeris.caps.credentialstore.internal.repository.PostgresCredentialRepository;
import eu.exeris.caps.credentialstore.spi.NotificationDispatcher;
import eu.exeris.caps.credentialstore.spi.SessionStore;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder;
import eu.exeris.sdk.annotation.capability.CapabilityLifecycle;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;
import eu.exeris.sdk.annotation.capability.Requires;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
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
 * <p>The composition conductor instantiates this class through its no-arg constructor to run the lifecycle
 * hooks, and that instance carries no services: the kernel SPIs this cap needs (a
 * {@link KernelPasswordEncoder} and a {@link TransactionalExecutor}) have no {@code ServiceLoader} lifecycle,
 * and ADR-099 obligation 6 forbids a cap from naming a driver class to find one. The composing SKU builds
 * the wired instance with {@link #CredentialStoreModule(TransactionalExecutor, KernelPasswordEncoder,
 * NotificationDispatcher, SessionStore, AuditLogSink, LockoutPolicy, TokenPolicy)}, and applies
 * {@link #MIGRATIONS} to the database before it does. There is no in-memory store and no
 * fallback encoder: an instance without its dependencies refuses to hand out a service.
 *
 * @since 0.1.0
 */
@CapabilityModule
@CapabilityLifecycle
@Provides(service = CredentialStore.class, version = "2.0.0")
@Provides(service = AccountVerification.class, version = "2.0.0")
@Provides(service = CredentialRecovery.class, version = "2.0.0")
@Requires(service = NotificationDispatcher.class, versionRange = "[1.0.0,2.0.0)", optional = true)
@Requires(service = KernelPasswordEncoder.class, optional = true)
@Requires(service = TransactionalExecutor.class, optional = true)
@Requires(service = SessionStore.class, versionRange = "[1.0.0,2.0.0)", optional = true)
@Requires(service = AuditLogSink.class, versionRange = "[1.0.0,2.0.0)", optional = true)
public final class CredentialStoreModule implements CapabilityLifecycleHooks {

    /**
     * The schema migrations of this capability, in the order they apply, as classpath resource paths. The
     * capability does not apply them itself; the composing SKU does, before the first service call.
     */
    public static final List<String> MIGRATIONS = List.of(
            "db/migration/exeris-caps-credential-store/V1__create_credential_store.sql");

    private final CredentialStore credentialStore;
    private final AccountVerification accountVerification;
    private final CredentialRecovery credentialRecovery;

    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean ready = new AtomicBoolean(false);

    /**
     * Lifecycle-only instance for reflective instantiation by the composition conductor. Its service
     * accessors throw {@link IllegalStateException}.
     */
    public CredentialStoreModule() {
        this.credentialStore = null;
        this.accountVerification = null;
        this.credentialRecovery = null;
    }

    /**
     * Wired instance over PostgreSQL through the kernel Persistence SPI.
     *
     * @param tx                     kernel transactional executor; required
     * @param passwordEncoder        kernel password encoder, Argon2id in a production composition; required
     * @param notificationDispatcher delivery of verification and reset tokens; required
     * @param sessionStore           session revocation on a password change or reset; {@code null} when the
     *                               composition carries no session store
     * @param auditLogSink           security audit sink; {@code null} when the composition carries none
     * @param lockoutPolicy          failed-attempt lockout; required
     * @param tokenPolicy            token lifetimes and issue cooldown; required
     */
    public CredentialStoreModule(
            TransactionalExecutor tx,
            KernelPasswordEncoder passwordEncoder,
            NotificationDispatcher notificationDispatcher,
            SessionStore sessionStore,
            AuditLogSink auditLogSink,
            LockoutPolicy lockoutPolicy,
            TokenPolicy tokenPolicy
    ) {
        this(
                new PostgresCredentialRepository(Objects.requireNonNull(tx, "tx must not be null")),
                passwordEncoder,
                new KdfConcurrencyThrottler(),
                notificationDispatcher,
                sessionStore,
                auditLogSink != null ? new AuditTrailBridge(auditLogSink) : null,
                lockoutPolicy,
                tokenPolicy,
                Clock.systemUTC()
        );
    }

    /** Wiring over an internal repository; package-private because its parameter types are internal. */
    CredentialStoreModule(
            CredentialRepository repository,
            KernelPasswordEncoder passwordEncoder,
            KdfConcurrencyThrottler throttler,
            NotificationDispatcher notificationDispatcher,
            SessionStore sessionStore,
            AuditTrailBridge auditTrail,
            LockoutPolicy lockoutPolicy,
            TokenPolicy tokenPolicy,
            Clock clock
    ) {
        Objects.requireNonNull(repository, "repository must not be null");
        Objects.requireNonNull(notificationDispatcher, "notificationDispatcher must not be null");
        Objects.requireNonNull(lockoutPolicy, "lockoutPolicy must not be null");
        Objects.requireNonNull(tokenPolicy, "tokenPolicy must not be null");
        Objects.requireNonNull(clock, "clock must not be null");
        PasswordHashing hashing = new PasswordHashing(
                Objects.requireNonNull(passwordEncoder, "passwordEncoder must not be null"),
                Objects.requireNonNull(throttler, "throttler must not be null"));

        this.credentialStore = new DefaultCredentialStore(
                repository, hashing, lockoutPolicy, sessionStore, auditTrail, clock);
        this.accountVerification = new DefaultAccountVerification(
                repository, notificationDispatcher, auditTrail, tokenPolicy, clock);
        this.credentialRecovery = new DefaultCredentialRecovery(
                repository, hashing, notificationDispatcher, sessionStore, auditTrail, tokenPolicy, clock);
    }

    public CredentialStore credentialStore() {
        return wired(credentialStore);
    }

    public AccountVerification accountVerification() {
        return wired(accountVerification);
    }

    public CredentialRecovery credentialRecovery() {
        return wired(credentialRecovery);
    }

    private static <T> T wired(T service) {
        if (service == null) {
            throw new IllegalStateException("CredentialStoreModule was instantiated without its dependencies; "
                    + "the composing SKU supplies them through the wiring constructor");
        }
        return service;
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
