package org.pqcfuzz.report;

/**
 * The verdict on one pre-registered hypothesis (design §4).
 *
 * @param id the hypothesis label, e.g. {@code H1}
 * @param statement what was predicted, before any data was collected
 * @param verdict how the campaign came out
 * @param evidence the counts the verdict rests on, so a reader can check it
 */
public record Hypothesis(String id, String statement, Verdict verdict, String evidence) {

    /**
     * Whether the campaign bore a hypothesis out.
     *
     * <p>{@link #NOT_SUPPORTED} is deliberately not called "refuted", and the distinction is the point
     * of pre-registering. Predicting no defects and finding none is weak evidence bounded by the input
     * budget; predicting defects and finding none may only mean the budget was too small. An absence
     * here never proves absence — it is assurance, at a stated cost (design §8).
     */
    public enum Verdict {
        /** The campaign came out as predicted. */
        SUPPORTED,
        /** The campaign contradicted the prediction — for these hypotheses, usually a real finding. */
        NOT_SUPPORTED
    }

    public static Hypothesis supported(String id, String statement, String evidence) {
        return new Hypothesis(id, statement, Verdict.SUPPORTED, evidence);
    }

    public static Hypothesis notSupported(String id, String statement, String evidence) {
        return new Hypothesis(id, statement, Verdict.NOT_SUPPORTED, evidence);
    }
}
