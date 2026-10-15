package eu.exeris.caps.credentialstore;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The audit-trail capability is an optional dependency, so the module must load, reflect and be constructed
 * for lifecycle with its jar absent from the class path.
 */
@DisplayName("Credential store without the optional audit-trail jar")
class CredentialStoreOptionalDependencyTest {

    private static final String HIDDEN_PREFIX = "eu.exeris.caps.audittrail.";
    private static final String OWN_PREFIX = "eu.exeris.caps.credentialstore.";

    /** Defines this capability's classes itself and refuses to see the audit-trail types. */
    private static final class WithoutAuditTrail extends ClassLoader {

        WithoutAuditTrail() {
            super(CredentialStoreOptionalDependencyTest.class.getClassLoader());
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (name.startsWith(HIDDEN_PREFIX)) {
                throw new ClassNotFoundException(name);
            }
            if (!name.startsWith(OWN_PREFIX)) {
                return super.loadClass(name, resolve);
            }
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    try (InputStream in = getParent().getResourceAsStream(name.replace('.', '/') + ".class")) {
                        if (in == null) {
                            throw new ClassNotFoundException(name);
                        }
                        byte[] bytes = in.readAllBytes();
                        loaded = defineClass(name, bytes, 0, bytes.length);
                    } catch (IOException e) {
                        throw new ClassNotFoundException(name, e);
                    }
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            }
        }
    }

    @Test
    @DisplayName("the audit-trail types really are hidden from the probe class loader")
    void probeHidesTheJar() {
        ClassLoader probe = new WithoutAuditTrail();
        assertThatThrownBy(() -> probe.loadClass("eu.exeris.caps.audittrail.api.AuditLogSink"))
                .isInstanceOf(ClassNotFoundException.class);
    }

    @Test
    @DisplayName("the module's constructors, methods and the lifecycle instance resolve without the jar")
    void moduleLoadsWithoutTheJar() throws Exception {
        Class<?> module = new WithoutAuditTrail().loadClass(CredentialStoreModule.class.getName());

        assertThat(module.getConstructors()).isNotEmpty();
        assertThat(module.getDeclaredConstructors()).isNotEmpty();
        assertThat(module.getMethods()).isNotEmpty();
        assertThat(module.getDeclaredMethods()).isNotEmpty();
        assertThat(module.getConstructor().newInstance()).isNotNull();
    }
}
