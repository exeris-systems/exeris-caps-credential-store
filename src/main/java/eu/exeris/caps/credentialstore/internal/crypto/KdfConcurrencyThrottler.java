package eu.exeris.caps.credentialstore.internal.crypto;

import java.util.concurrent.Semaphore;
import java.util.function.Supplier;

/**
 * Throttles concurrent Argon2id KDF operations to prevent memory exhaustion (OOM) and CPU starvation
 * under heavy virtual thread traffic.
 *
 * <p>Limits concurrency to {@code max(4, 2 * availableProcessors)} by default. {@link #execute} waits for a
 * permit without a bound, so the caller bounds the queue (a connection limit or a rate limit in front of the
 * sign-in endpoint).
 *
 * @since 0.1.0
 */
public final class KdfConcurrencyThrottler {

    private final Semaphore semaphore;
    private final int maxConcurrent;

    public KdfConcurrencyThrottler() {
        this(Math.max(4, Runtime.getRuntime().availableProcessors() * 2));
    }

    public KdfConcurrencyThrottler(int maxConcurrent) {
        if (maxConcurrent < 1) {
            throw new IllegalArgumentException("maxConcurrent must be >= 1");
        }
        this.maxConcurrent = maxConcurrent;
        this.semaphore = new Semaphore(maxConcurrent, true);
    }

    public int maxConcurrent() {
        return maxConcurrent;
    }

    public int availablePermits() {
        return semaphore.availablePermits();
    }

    /**
     * Executes the given KDF supplier within a throttled permit boundary.
     *
     * @param operation operation to execute
     * @param <T> result type
     * @return operation result
     */
    public <T> T execute(Supplier<T> operation) {
        try {
            semaphore.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for KDF execution permit", e);
        }
        try {
            return operation.get();
        } finally {
            semaphore.release();
        }
    }

    /**
     * Executes the given KDF runnable within a throttled permit boundary.
     *
     * @param operation runnable to execute
     */
    public void execute(Runnable operation) {
        execute(() -> {
            operation.run();
            return null;
        });
    }
}
