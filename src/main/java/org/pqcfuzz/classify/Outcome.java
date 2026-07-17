package org.pqcfuzz.classify;

/**
 * The classification of a single (target, input) execution — the core instrument of this study, fixed
 * before data collection (see {@code docs/EXPERIMENT-DESIGN.md} §6).
 *
 * <p>The distinction that matters is {@link #REJECTED} versus {@link #UNEXPECTED_EXCEPTION}: both are
 * "the target threw or returned false", but only the former is the contractually correct way to refuse
 * hostile bytes. {@link #ACCEPTED} and {@link #TIMEOUT} are the severe outcomes.
 */
public enum Outcome {

    /**
     * The target accepted an input it is allowed to accept: a genuine signature that verified, or a
     * correct-length encoding that parsed. Not a defect.
     *
     * <p>Note for decoders: a <em>correct-length</em> key encoding that parses successfully is
     * {@code OK}, not a defect, however corrupt its contents. PQC public keys are unstructured byte
     * strings of a fixed length, so a mutated encoding of the right length is a well-formed (if
     * cryptographically useless) key, and the decoder is right to accept it. A <em>wrong-length</em>
     * encoding is a different matter — see {@link #ACCEPTED}.
     */
    OK,

    /**
     * The contractually correct response to malformed input: verify returned {@code false}, or the
     * target threw a documented rejection exception (see {@link ExpectedRejections}). Not a defect.
     */
    REJECTED,

    /**
     * The target threw a {@code Throwable} outside the documented rejection whitelist — an
     * {@code ArrayIndexOutOfBoundsException}, {@code NegativeArraySizeException},
     * {@code NullPointerException}, {@code OutOfMemoryError}, or similar. The primary defect class:
     * at minimum a denial-of-service vector on a path that is reachable by any network peer.
     */
    UNEXPECTED_EXCEPTION,

    /**
     * The target exceeded the per-input time budget — a potential algorithmic-complexity denial of
     * service, or a non-terminating loop.
     */
    TIMEOUT,

    /**
     * The target accepted an input it should have refused. Two forms, both defects:
     *
     * <ul>
     *   <li><b>A forgery.</b> A verify path returned {@code true} for a signature that is not genuine.
     *       The most severe outcome available: a break of the implementation.
     *   <li><b>A wrong-length encoding parsed.</b> A decoder accepted an input that is not the length
     *       its wire format defines. These formats are fixed-length, so a wrong length is malformed by
     *       definition and there is nothing to interpret.
     * </ul>
     *
     * <p>The second form was added after the instrument proved blind to a real defect. BouncyCastle
     * 1.84's ML-DSA decoder performs no length check and accepts any encoding of 33 bytes or more,
     * including a 1 MiB one — a defect BouncyCastle fixed in 1.85. Scoring that {@code OK} because
     * "nothing was thrown" would have recorded a missing validation as correct behaviour. Silently
     * accepting a malformed encoding is worse than throwing on it: the caller has no idea anything is
     * wrong, and the error surfaces later, further from its cause — as an
     * {@code ArrayIndexOutOfBoundsException} once the bogus key is actually used.
     */
    ACCEPTED;

    /** Whether this outcome is a defect worth triaging and reporting. */
    public boolean isAnomaly() {
        return this == UNEXPECTED_EXCEPTION || this == TIMEOUT || this == ACCEPTED;
    }
}
