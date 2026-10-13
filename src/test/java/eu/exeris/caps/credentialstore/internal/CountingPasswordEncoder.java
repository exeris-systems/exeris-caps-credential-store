package eu.exeris.caps.credentialstore.internal;

import eu.exeris.caps.credentialstore.api.RehashablePasswordEncoder;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * The kernel community Argon2id encoder at its minimum cost, counting derivations. Hashes listed as legacy
 * are reported as needing a rehash, and verified as if they were Argon2id hashes of {@link #LEGACY_PASSWORD}.
 */
public final class CountingPasswordEncoder implements KernelPasswordEncoder, RehashablePasswordEncoder {

    public static final String LEGACY_HASH = "$2a$10$legacylegacylegacylegacylegacylegacylegacylegacyleg";
    public static final String LEGACY_PASSWORD = "LegacyPassword1!";

    private final KernelPasswordEncoder delegate =
            new Argon2idPasswordEncoder(new PasswordEncoderConfig(8192, 1, 1, 16));
    private final String legacyAsArgon = delegate.encode(LEGACY_PASSWORD.toCharArray());
    private final AtomicInteger matches = new AtomicInteger();
    private final AtomicInteger encodes = new AtomicInteger();

    @Override
    public String encode(char[] raw) {
        encodes.incrementAndGet();
        return delegate.encode(raw);
    }

    @Override
    public boolean matches(char[] raw, String encoded) {
        matches.incrementAndGet();
        return delegate.matches(raw, LEGACY_HASH.equals(encoded) ? legacyAsArgon : encoded);
    }

    @Override
    public boolean needsRehash(String encoded) {
        return LEGACY_HASH.equals(encoded);
    }

    public int matchCount() {
        return matches.get();
    }

    public int encodeCount() {
        return encodes.get();
    }
}
