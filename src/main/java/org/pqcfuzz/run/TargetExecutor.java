package org.pqcfuzz.run;

import org.pqcfuzz.classify.Classifier;
import org.pqcfuzz.classify.Outcome;
import org.pqcfuzz.target.FuzzTarget;

import java.util.concurrent.TimeoutException;

/**
 * Drives one target through the full pipeline — run under a time bound, classify the result — and is
 * the single place an input is ever executed. The campaign loop and the {@link Minimizer} share it, so
 * a minimized reproducer is judged by exactly the rules that flagged the original.
 */
final class TargetExecutor implements AutoCloseable {

    private final FuzzTarget target;
    private final Classifier classifier;
    private final TimeBoundedRunner runner;

    TargetExecutor(FuzzTarget target, long timeoutMillis) {
        this.target = target;
        this.classifier = new Classifier(target);
        this.runner = new TimeBoundedRunner(timeoutMillis);
    }

    int abandonedThreads() {
        return runner.abandonedThreads();
    }

    /**
     * Execute one input and classify what happened.
     *
     * <p>Catching {@code Throwable} is intentional and is the whole point: an {@code OutOfMemoryError}
     * or {@code StackOverflowError} provoked by hostile bytes is a finding to be recorded, not a reason
     * to abandon the campaign. The two throwables that are <em>not</em> the target's behaviour are
     * re-thrown instead: an interrupt is the operator stopping us, and
     * {@link TimeBoundedRunner.TooManyHangsException} means the host is too contended for further
     * results to mean anything. Both are the harness's own signals, and both have types no library
     * would throw, so neither can be confused with a finding.
     */
    Execution execute(byte[] input) {
        try {
            boolean accepted = runner.call(() -> target.accepts(input));
            return new Execution(classifier.classifyReturn(input, accepted), null);
        } catch (TimeoutException e) {
            return new Execution(Outcome.TIMEOUT, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CampaignInterruptedException(e);
        } catch (TimeBoundedRunner.TooManyHangsException e) {
            throw e;
        } catch (Throwable t) {
            return new Execution(classifier.classifyThrow(t), t);
        }
    }

    @Override
    public void close() {
        runner.close();
    }

    /** Thrown when the operator interrupts a campaign; never a finding about the library. */
    static final class CampaignInterruptedException extends RuntimeException {
        CampaignInterruptedException(Throwable cause) {
            super("Campaign interrupted", cause);
        }
    }
}
