package org.pqcfuzz.mutate;

/**
 * One generated input together with the provenance needed to reproduce and explain it: which seed it
 * came from and which strategy damaged it. Anomaly reports carry this so a finding reads as "a
 * truncation of seed 0", not just an opaque blob.
 */
public record MutatedInput(byte[] bytes, Mutation mutation, int seedIndex) {

    /** A short human-readable provenance, e.g. {@code TRUNCATE(seed 0) -> 512 bytes}. */
    public String describe() {
        return mutation + "(seed " + seedIndex + ") -> " + bytes.length + " bytes";
    }
}
