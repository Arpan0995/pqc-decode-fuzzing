package org.pqcfuzz.run;

import org.pqcfuzz.classify.Outcome;
import org.pqcfuzz.mutate.Mutation;
import org.pqcfuzz.target.TargetKind;

import java.util.List;
import java.util.Map;

/**
 * Everything one target's campaign produced (design §7): what it executed, how the outcomes fell out
 * overall and per mutation strategy, and the distinct anomalies with their reproducers.
 *
 * @param targetName the target under test
 * @param kind its contract
 * @param nominalInputLength the length of a well-formed input, in bytes
 * @param inputsExecuted how many inputs were driven through the target
 * @param elapsedNanos wall-clock time for the campaign
 * @param outcomes total count per outcome
 * @param outcomesByMutation count per outcome, broken down by the strategy that generated the input
 * @param outcomesAtNominalLength count per outcome over only the correct-length inputs
 * @param anomalies the distinct defects found, most-hit first
 * @param abandonedThreads threads leaked to hung calls — nonzero means throughput here is contended
 */
public record TargetResult(
        String targetName,
        TargetKind kind,
        int nominalInputLength,
        long inputsExecuted,
        long elapsedNanos,
        Map<Outcome, Long> outcomes,
        Map<Mutation, Map<Outcome, Long>> outcomesByMutation,
        Map<Outcome, Long> outcomesAtNominalLength,
        List<Anomaly> anomalies,
        int abandonedThreads) {

    public long count(Outcome outcome) {
        return outcomes.getOrDefault(outcome, 0L);
    }

    /**
     * Count per outcome over inputs of exactly {@link #nominalInputLength()} bytes — the ones that pass
     * any length check and reach the real parsing and arithmetic.
     *
     * <p>This split carries the sharpest claim in the study. A decoder that throws
     * {@code ArrayIndexOutOfBounds} on a truncated input is careless; one that does so on a
     * correct-length input has a bug in its actual unpacking, which is a different and more serious
     * thing. It is also the only way to test H3, whose whole content is about correct-length ciphertexts.
     */
    public long countAtNominalLength(Outcome outcome) {
        return outcomesAtNominalLength.getOrDefault(outcome, 0L);
    }

    /** Inputs per second — exploratory, and host-specific (design §8). */
    public double inputsPerSecond() {
        double seconds = elapsedNanos / 1_000_000_000.0;
        return seconds > 0 ? inputsExecuted / seconds : 0;
    }

    /** Whether anything worth triaging turned up. */
    public boolean hasAnomalies() {
        return !anomalies.isEmpty();
    }
}
