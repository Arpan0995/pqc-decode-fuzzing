package org.pqcfuzz.run;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Runs each input under a wall-clock budget, so that a hang is an observation rather than a hung
 * campaign. Detecting hangs is a stated goal (RQ1, H4) — an algorithmic-complexity blow-up in a verify
 * path is a denial-of-service vector — and a hang cannot be detected from the thread that is hung.
 *
 * <p><b>A timed-out call cannot be stopped.</b> Java has no safe way to kill a running computation:
 * {@code Thread.interrupt} only works on code that checks for it, and BouncyCastle's inner loops do not.
 * {@code Thread.stop} is gone. So a timeout here leaks a thread that keeps burning a core until the JVM
 * exits, and every subsequent input runs alongside it. This class therefore treats a timeout as
 * something to <em>report and bound</em>, never to recover from silently:
 *
 * <ul>
 *   <li>The worker runs on a daemon thread, so leaked threads can never keep the JVM alive.
 *   <li>After a timeout the executor is discarded and a fresh one built, so the next input starts on a
 *       clean thread rather than queueing behind the hung one.
 *   <li>Abandoned threads are counted, and past {@link #MAX_ABANDONED_THREADS} the campaign is failed
 *       rather than allowed to grind on. A campaign with dozens of runaway threads is not measuring the
 *       library any more — its throughput figures are contended and worthless — and finding one real
 *       hang is a result in itself, worth stopping to triage.
 * </ul>
 *
 * <p>The per-input {@code Future} costs a thread hand-off on every execution, which is a real tax on the
 * fastest targets. That cost is accepted deliberately: throughput is exploratory here (design §8) while
 * hang detection is a research question, and an instrument that cannot see a hang is worse than a slow
 * one.
 */
final class TimeBoundedRunner implements AutoCloseable {

    /** Enough runaway threads to distort the host; past this the campaign is not measuring anything. */
    static final int MAX_ABANDONED_THREADS = 16;

    private static final ThreadFactory FACTORY = r -> {
        Thread t = new Thread(r, "pqcfuzz-target");
        t.setDaemon(true);
        return t;
    };

    private final long timeoutMillis;
    private ExecutorService executor = Executors.newSingleThreadExecutor(FACTORY);
    private int abandonedThreads;

    TimeBoundedRunner(long timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
    }

    /** Number of threads abandoned to hung calls so far. */
    int abandonedThreads() {
        return abandonedThreads;
    }

    /**
     * Run {@code task} under the budget.
     *
     * @return the task's value
     * @throws TimeoutException if the budget elapsed; the call is still running and its thread is now
     *     abandoned
     * @throws Throwable whatever the task threw, unwrapped
     */
    boolean call(Callable<Boolean> task) throws Throwable {
        Future<Boolean> future = executor.submit(task);
        try {
            return future.get(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (ExecutionException e) {
            // The task threw; hand the caller the real throwable, not the executor's wrapper.
            throw e.getCause();
        } catch (TimeoutException e) {
            abandon(future);
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw e;
        }
    }

    /**
     * Give up on a hung call: ask it to stop (it almost certainly will not), then replace the executor
     * so the next input is not queued behind a thread that will never finish.
     */
    private void abandon(Future<Boolean> future) {
        future.cancel(true);
        executor.shutdownNow();
        abandonedThreads++;
        if (abandonedThreads > MAX_ABANDONED_THREADS) {
            throw new TooManyHangsException(
                    "Abandoned " + abandonedThreads + " threads to hung calls (limit "
                            + MAX_ABANDONED_THREADS + "). Stopping: the host is now contended, so any "
                            + "further measurement is unreliable. The hangs already recorded are the "
                            + "finding — triage those.");
        }
        executor = Executors.newSingleThreadExecutor(FACTORY);
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }

    /**
     * Signals that too many calls hung to keep measuring. This has its own type on purpose: the
     * campaign must abort on it, but must <em>not</em> abort on the superficially similar exceptions a
     * target might throw. BouncyCastle throwing {@code IllegalStateException} at hostile bytes is an
     * anomaly to record and keep fuzzing past — reusing a stock exception type here would make the
     * harness mistake a finding for its own stop signal and silently truncate the campaign.
     */
    static final class TooManyHangsException extends RuntimeException {
        TooManyHangsException(String message) {
            super(message);
        }
    }
}
