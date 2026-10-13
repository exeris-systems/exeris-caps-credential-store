package eu.exeris.caps.credentialstore.internal.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("KdfConcurrencyThrottler Unit Tests")
class KdfConcurrencyThrottlerTest {

    @Test
    @DisplayName("rejects non-positive concurrency permits")
    void rejectsInvalidPermits() {
        assertThatThrownBy(() -> new KdfConcurrencyThrottler(0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new KdfConcurrencyThrottler(-1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("executes single operation and preserves permit count")
    void executesSingleOperation() {
        KdfConcurrencyThrottler throttler = new KdfConcurrencyThrottler(4);
        assertThat(throttler.availablePermits()).isEqualTo(4);

        String result = throttler.execute(() -> "success");
        assertThat(result).isEqualTo("success");
        assertThat(throttler.availablePermits()).isEqualTo(4);
    }

    @Test
    @DisplayName("releases permit when operation throws exception")
    void releasesPermitOnException() {
        KdfConcurrencyThrottler throttler = new KdfConcurrencyThrottler(2);

        assertThatThrownBy(() -> throttler.execute(() -> {
            throw new RuntimeException("KDF failed");
        })).isInstanceOf(RuntimeException.class).hasMessage("KDF failed");

        assertThat(throttler.availablePermits()).isEqualTo(2);
    }

    @Test
    @DisplayName("throttles concurrent operations to configured maximum permits")
    void throttlesConcurrentOperations() throws Exception {
        int maxPermits = 2;
        KdfConcurrencyThrottler throttler = new KdfConcurrencyThrottler(maxPermits);

        CountDownLatch thread1Started = new CountDownLatch(1);
        CountDownLatch thread2Started = new CountDownLatch(1);
        CountDownLatch releaseHold = new CountDownLatch(1);
        AtomicInteger activeConcurrent = new AtomicInteger(0);
        AtomicInteger maxObserved = new AtomicInteger(0);

        Runnable task = () -> throttler.execute(() -> {
            int current = activeConcurrent.incrementAndGet();
            maxObserved.updateAndGet(max -> Math.max(max, current));
            if (current == 1) {
                thread1Started.countDown();
            } else if (current == 2) {
                thread2Started.countDown();
            }
            try {
                releaseHold.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                activeConcurrent.decrementAndGet();
            }
            return null;
        });

        Thread t1 = Thread.ofVirtual().start(task);
        Thread t2 = Thread.ofVirtual().start(task);

        assertThat(thread1Started.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(thread2Started.await(2, TimeUnit.SECONDS)).isTrue();

        // With 2 permits occupied, a 3rd thread must wait and not enter
        AtomicBoolean t3EnteredEarly = new AtomicBoolean(false);
        Thread t3 = Thread.ofVirtual().start(() -> {
            throttler.execute(() -> {
                t3EnteredEarly.set(true);
                return null;
            });
        });

        Thread.sleep(100);
        assertThat(t3EnteredEarly.get()).isFalse();
        assertThat(throttler.availablePermits()).isZero();

        // Release first two
        releaseHold.countDown();
        t1.join();
        t2.join();
        t3.join();

        assertThat(maxObserved.get()).isEqualTo(2);
        assertThat(throttler.availablePermits()).isEqualTo(2);
    }
}
