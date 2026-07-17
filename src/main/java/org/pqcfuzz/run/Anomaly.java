package org.pqcfuzz.run;

import org.pqcfuzz.classify.AnomalySignature;
import org.pqcfuzz.mutate.Mutation;

/**
 * One distinct defect: a {@link AnomalySignature} plus how often it fired and one input that reaches
 * it. Thousands of crashing inputs collapse into a handful of these, which is what makes the results
 * triageable and what a maintainer needs in a disclosure.
 */
public final class Anomaly {

    private final AnomalySignature signature;
    private final String detail;
    private final String stackTrace;

    private byte[] reproducer;
    private Mutation mutation;
    private int seedIndex;
    private long count;

    Anomaly(AnomalySignature signature, String detail, String stackTrace,
            byte[] reproducer, Mutation mutation, int seedIndex) {
        this.signature = signature;
        this.detail = detail;
        this.stackTrace = stackTrace;
        this.reproducer = reproducer;
        this.mutation = mutation;
        this.seedIndex = seedIndex;
        this.count = 1;
    }

    /**
     * Record another hit on this signature, keeping the shorter input as the reproducer.
     *
     * <p>Preferring shorter is a cheap first pass at minimality — a 3-byte input that trips the same
     * bug as a 17088-byte one tells the whole story on its own. {@link Minimizer} does the real
     * shrinking afterwards, on this survivor.
     */
    void recordHit(byte[] input, Mutation mutation, int seedIndex) {
        count++;
        if (input.length < reproducer.length) {
            this.reproducer = input;
            this.mutation = mutation;
            this.seedIndex = seedIndex;
        }
    }

    void replaceReproducer(byte[] minimized) {
        this.reproducer = minimized;
    }

    public AnomalySignature signature() {
        return signature;
    }

    /** The exception's message, or {@code ""} — often the most informative single line in a report. */
    public String detail() {
        return detail;
    }

    public String stackTrace() {
        return stackTrace;
    }

    public byte[] reproducer() {
        return reproducer;
    }

    public Mutation mutation() {
        return mutation;
    }

    public int seedIndex() {
        return seedIndex;
    }

    /** How many inputs hit this signature — a rough measure of how easy the defect is to reach. */
    public long count() {
        return count;
    }
}
