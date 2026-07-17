package org.pqcfuzz.target;

/**
 * What kind of contract a target is held to. This decides how an "accept" is read: accepting a
 * non-genuine input is a forgery for a {@link #VERIFY} target, but perfectly correct for a
 * {@link #DECODE} target.
 */
public enum TargetKind {

    /**
     * A signature verification path. Must be <em>total</em>: for any input it returns true or false and
     * never throws. Accepting anything but a genuine signature is a forgery
     * ({@link org.pqcfuzz.classify.Outcome#ACCEPTED}).
     */
    VERIFY,

    /**
     * An encoding parser (public keys). May refuse malformed input by throwing a documented exception;
     * accepting a mutated encoding is not in itself a defect, since a fixed-length PQC key is an
     * unstructured byte string.
     */
    DECODE,

    /**
     * ML-KEM decapsulation. Special: by the Fujisaki–Okamoto transform it has no "reject" — a
     * correct-length ciphertext always yields a secret (the real one, or a pseudorandom implicit
     * rejection value). It must therefore never throw for a correct-length input.
     */
    DECAPSULATE
}
