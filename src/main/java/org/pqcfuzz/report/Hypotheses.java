package org.pqcfuzz.report;

import org.pqcfuzz.classify.Outcome;
import org.pqcfuzz.run.TargetResult;
import org.pqcfuzz.target.TargetKind;

import java.util.ArrayList;
import java.util.List;

/**
 * Scores the campaign against the four hypotheses registered in the design (§4) before any data
 * existed.
 *
 * <p>Doing this in code rather than in prose is the whole value of having pre-registered. The
 * hypotheses were fixed in advance precisely so that the result could not be reinterpreted after the
 * fact to match whatever turned up, and a rule expressed as code cannot quietly soften when the numbers
 * come in. It also means a clean assurance result and a defect finding are produced by the same
 * mechanism and carry the same weight.
 *
 * <p>Every verdict must be evaluable only from a {@link TargetResult}: any hypothesis needing a
 * judgement call is one the design should have stated more sharply.
 */
public final class Hypotheses {

    private Hypotheses() {
    }

    /** Evaluate all four hypotheses against a completed campaign. */
    public static List<Hypothesis> evaluate(List<TargetResult> results) {
        List<Hypothesis> verdicts = new ArrayList<>(4);
        verdicts.add(evaluateH1(results));
        verdicts.add(evaluateH2(results));
        verdicts.add(evaluateH3(results));
        verdicts.add(evaluateH4(results));
        return List.copyOf(verdicts);
    }

    /** H1: verify paths are total — no uncaught exception, no forgery accepted. */
    private static Hypothesis evaluateH1(List<TargetResult> results) {
        String statement = "The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes"
                + " an uncaught exception or a forgery acceptance.";
        List<TargetResult> verifiers = ofKind(results, TargetKind.VERIFY);
        long exceptions = total(verifiers, Outcome.UNEXPECTED_EXCEPTION);
        long forgeries = total(verifiers, Outcome.ACCEPTED);
        long inputs = totalInputs(verifiers);

        String evidence = String.format(
                "%,d inputs across %d verify target(s): %,d undocumented exception(s), %,d forgery"
                        + " acceptance(s).",
                inputs, verifiers.size(), exceptions, forgeries);
        return exceptions == 0 && forgeries == 0
                ? Hypothesis.supported("H1", statement, evidence)
                : Hypothesis.notSupported("H1", statement, evidence);
    }

    /**
     * H2: fuzzing surfaces at least a few undocumented exceptions from the decoders.
     *
     * <p>Note the asymmetry with the others: this hypothesis predicts that defects <em>exist</em>, so
     * SUPPORTED here is the finding and NOT_SUPPORTED is the assurance result. That is not a mistake —
     * it is what makes the pre-registration honest, since it commits in advance to the outcome the
     * researcher would prefer.
     */
    private static Hypothesis evaluateH2(List<TargetResult> results) {
        String statement = "The public-key decoders mostly reject with documented exceptions, but fuzzing"
                + " surfaces at least one input triggering an undocumented runtime exception.";
        List<TargetResult> decoders = ofKind(results, TargetKind.DECODE);
        long exceptions = total(decoders, Outcome.UNEXPECTED_EXCEPTION);
        long wrongLengthAccepted = total(decoders, Outcome.ACCEPTED);
        long inputs = totalInputs(decoders);

        // The verdict turns only on exceptions, exactly as pre-registered. But a decoder can fail
        // without throwing — by swallowing a malformed encoding silently — and reporting only the
        // exception count would let that pass unmentioned under a "not supported" verdict. So the
        // evidence carries both, and the verdict carries only what H2 actually predicted.
        StringBuilder evidence = new StringBuilder(String.format(
                "%,d inputs across %d decode target(s): %,d undocumented exception(s).",
                inputs, decoders.size(), exceptions));
        if (wrongLengthAccepted > 0) {
            evidence.append(String.format(
                    " Separately, %,d wrong-length encoding(s) were silently **accepted** — a decoder"
                            + " defect that H2 did not anticipate, since it fails without throwing.",
                    wrongLengthAccepted));
        }
        return exceptions > 0
                ? Hypothesis.supported("H2", statement, evidence.toString())
                : Hypothesis.notSupported("H2", statement, evidence.toString());
    }

    /**
     * H3: {@code extractSecret} never throws for a correct-length ciphertext (implicit rejection holds).
     *
     * <p>Only the correct-length inputs bear on this, which is exactly what
     * {@link TargetResult#countAtNominalLength} isolates. The hypothesis makes no claim about
     * wrong-length inputs, and folding those in would test something the design never predicted.
     */
    private static Hypothesis evaluateH3(List<TargetResult> results) {
        String statement = "ML-KEM decapsulation never throws for a correct-length ciphertext: the"
                + " Fujisaki-Okamoto implicit-rejection branch always returns a secret.";
        List<TargetResult> decaps = ofKind(results, TargetKind.DECAPSULATE);
        if (decaps.isEmpty()) {
            return Hypothesis.notSupported("H3", statement, "No decapsulation target ran.");
        }
        long correctLength = decaps.stream()
                .mapToLong(r -> r.outcomesAtNominalLength().values().stream().mapToLong(Long::longValue).sum())
                .sum();
        long threw = decaps.stream()
                .mapToLong(r -> r.countAtNominalLength(Outcome.UNEXPECTED_EXCEPTION)
                        + r.countAtNominalLength(Outcome.REJECTED))
                .sum();

        String evidence = String.format(
                "%,d correct-length ciphertext(s) decapsulated: %,d threw. (Wrong-length inputs are"
                        + " outside this hypothesis and are reported separately.)",
                correctLength, threw);
        if (correctLength == 0) {
            return Hypothesis.notSupported("H3", statement,
                    "No correct-length ciphertext was ever generated, so the hypothesis went untested.");
        }
        return threw == 0
                ? Hypothesis.supported("H3", statement, evidence)
                : Hypothesis.notSupported("H3", statement, evidence);
    }

    /** H4: no input hangs within the time budget. */
    private static Hypothesis evaluateH4(List<TargetResult> results) {
        String statement = "No input causes a hang (non-termination or super-linear blow-up) within the"
                + " per-input time budget.";
        long timeouts = total(results, Outcome.TIMEOUT);
        String evidence = String.format("%,d input(s) across %d target(s): %,d timeout(s).",
                totalInputs(results), results.size(), timeouts);
        return timeouts == 0
                ? Hypothesis.supported("H4", statement, evidence)
                : Hypothesis.notSupported("H4", statement, evidence);
    }

    private static List<TargetResult> ofKind(List<TargetResult> results, TargetKind kind) {
        return results.stream().filter(r -> r.kind() == kind).toList();
    }

    private static long total(List<TargetResult> results, Outcome outcome) {
        return results.stream().mapToLong(r -> r.count(outcome)).sum();
    }

    private static long totalInputs(List<TargetResult> results) {
        return results.stream().mapToLong(TargetResult::inputsExecuted).sum();
    }
}
