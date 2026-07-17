package org.pqcfuzz.run;

import org.pqcfuzz.classify.AnomalySignature;
import org.pqcfuzz.classify.Outcome;

/**
 * What one input did: its classified {@link Outcome} and, if it threw, the throwable itself.
 *
 * @param outcome the classification
 * @param thrown what the target threw, or null if it returned or timed out
 */
public record Execution(Outcome outcome, Throwable thrown) {

    /** The signature identifying this execution's defect. Only meaningful when the outcome is an anomaly. */
    public AnomalySignature signature() {
        return thrown == null
                ? AnomalySignature.of(outcome)
                : AnomalySignature.of(outcome, thrown);
    }

    /** The throwable's message, or {@code ""} if there was none. */
    public String detail() {
        if (thrown == null) {
            return "";
        }
        String message = thrown.getMessage();
        return message == null ? "" : message;
    }
}
