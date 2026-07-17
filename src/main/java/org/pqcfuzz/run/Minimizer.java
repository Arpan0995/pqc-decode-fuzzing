package org.pqcfuzz.run;

import org.pqcfuzz.classify.AnomalySignature;

import java.util.Arrays;

/**
 * Shrinks a crashing input to a small one that still trips the same defect (design §6).
 *
 * <p>A raw reproducer from this campaign is a 17088-byte signature with a few bits flipped, and it
 * answers nothing on its own: a maintainer cannot see which of those bytes matter, and neither can the
 * researcher writing up the finding. Shrinking the same crash to "1088 zero bytes" or "a 3-byte input"
 * turns the reproducer into the explanation — that is the difference between a bug report and a bug
 * report someone can act on.
 *
 * <p>Two passes, each keeping any candidate that still produces the identical
 * {@link AnomalySignature}:
 *
 * <ol>
 *   <li><b>Length.</b> Trim bytes off the end, halving the trim size on failure. Resolves whether a
 *       defect is about length at all.
 *   <li><b>Content.</b> Zero out spans, halving the span on each sweep. What survives is the input with
 *       as much as possible blanked, so the bytes left non-zero are the ones the defect depends on.
 * </ol>
 *
 * <p>This is greedy, not optimal: it returns a small input, not the provably smallest one, and it holds
 * the signature fixed rather than merely the outcome, so a defect reachable by several routes minimizes
 * per route. Both are the right trade for triage, and both are bounded by {@link #MAX_ATTEMPTS} so that
 * minimizing never costs more than the campaign that found the bug.
 */
final class Minimizer {

    /** Execution budget per anomaly. Generous for a handful of defects, negligible against a campaign. */
    static final int MAX_ATTEMPTS = 400;

    private final TargetExecutor executor;
    private int attempts;

    Minimizer(TargetExecutor executor) {
        this.executor = executor;
    }

    /**
     * Return a small input producing {@code signature}, or {@code input} unchanged if nothing smaller
     * was found within the budget.
     */
    byte[] minimize(byte[] input, AnomalySignature signature) {
        attempts = 0;
        byte[] best = shrinkLength(input, signature);
        return blankContent(best, signature);
    }

    /** Trim from the end, largest bite first, restarting after each success. */
    private byte[] shrinkLength(byte[] input, AnomalySignature signature) {
        byte[] best = input;
        for (int trim = best.length / 2; trim >= 1 && attempts < MAX_ATTEMPTS; ) {
            if (trim >= best.length) {
                trim /= 2;
                continue;
            }
            byte[] candidate = Arrays.copyOf(best, best.length - trim);
            if (reproduces(candidate, signature)) {
                best = candidate;
                trim = Math.min(trim, Math.max(1, best.length / 2));
            } else {
                trim /= 2;
            }
        }
        return best;
    }

    /** Zero out spans, halving the span each sweep, keeping every blanking that preserves the defect. */
    private byte[] blankContent(byte[] input, AnomalySignature signature) {
        byte[] best = input;
        for (int span = Math.max(1, best.length / 2); span >= 1 && attempts < MAX_ATTEMPTS; span /= 2) {
            for (int start = 0; start + span <= best.length && attempts < MAX_ATTEMPTS; start += span) {
                if (isAlreadyBlank(best, start, span)) {
                    continue;
                }
                byte[] candidate = best.clone();
                Arrays.fill(candidate, start, start + span, (byte) 0);
                if (reproduces(candidate, signature)) {
                    best = candidate;
                }
            }
        }
        return best;
    }

    private static boolean isAlreadyBlank(byte[] buf, int start, int span) {
        for (int i = start; i < start + span; i++) {
            if (buf[i] != 0) {
                return false;
            }
        }
        return true;
    }

    private boolean reproduces(byte[] candidate, AnomalySignature signature) {
        attempts++;
        Execution execution = executor.execute(candidate);
        return execution.outcome().isAnomaly() && execution.signature().equals(signature);
    }
}
