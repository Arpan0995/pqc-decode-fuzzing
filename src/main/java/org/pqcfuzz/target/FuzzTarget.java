package org.pqcfuzz.target;

import java.util.List;

/**
 * One attacker-reachable entry point under test: a function that takes hostile bytes off the wire and
 * must handle them without throwing, hanging, or being fooled.
 *
 * <p>A target's job is only to <em>drive</em> the library and report what it did; deciding whether that
 * behaviour is a defect belongs to the classifier, so that the same rules apply to every target.
 *
 * <p><b>Every target must use {@code org.bouncycastle.crypto.{params,signers,generators,kems}}</b>, not
 * the {@code org.bouncycastle.pqc.crypto.*} packages. The two look interchangeable — same class names,
 * same signatures, and both compile — but BouncyCastle deprecated the {@code pqc.crypto} spelling, and
 * {@code PublicKeyFactory} returns the former when it parses an X.509 certificate. Since the claim this
 * study makes is about the code that real peers reach, fuzzing the deprecated shim would quietly
 * measure the wrong thing while looking identical in the results. The two are distinct classes with the
 * same simple name, so a stray import is easy to make and invisible afterwards.
 *
 * <p>Implementations are constructed with a seed and must be deterministic: the same seed yields the
 * same keys and the same {@link #seedCorpus()}, so any anomaly reproduces from the seed alone.
 * A single instance is driven from one thread at a time.
 */
public interface FuzzTarget {

    /** Stable identifier recorded in results, e.g. {@code ml-kem-768-decap}. */
    String name();

    /** The contract this target is held to. */
    TargetKind kind();

    /**
     * Well-formed inputs to seed and mutate from: genuine ciphertexts, signatures, or key encodings.
     *
     * <p>This is mutation <em>material</em>, and it may deliberately include structurally valid inputs
     * that the target should nonetheless refuse — a signature made with the wrong key, for instance, is
     * perfect fuzzing material precisely because it drives verification deep before failing. It is
     * therefore not the ground truth for forgery detection; see {@link #genuineInputs()}.
     */
    List<byte[]> seedCorpus();

    /**
     * The inputs this target is genuinely expected to accept. A {@link TargetKind#VERIFY} target
     * accepting anything outside this set is a forgery ({@link org.pqcfuzz.classify.Outcome#ACCEPTED}),
     * so the set must contain exactly the truly valid inputs and nothing else.
     *
     * <p>Defaults to the whole seed corpus, which is right for targets whose seeds are all valid
     * (the decoders and decapsulation). Verify targets seeded with wrong-key signatures must override.
     */
    default List<byte[]> genuineInputs() {
        return seedCorpus();
    }

    /** The length in bytes of a well-formed input, recorded in results and used by length mutators. */
    int nominalInputLength();

    /**
     * Drive the target with {@code input}.
     *
     * @return true if the target accepted the input (verify returned true, or the decode/decapsulation
     *     succeeded); false if it cleanly refused (verify returned false)
     * @throws Exception whatever the library throws; the classifier decides whether it was documented.
     *     {@code Error}s — an {@code OutOfMemoryError} from an attacker-chosen length, say — are
     *     unchecked and propagate likewise; the runner catches them and counts them as anomalies.
     */
    boolean accepts(byte[] input) throws Exception;
}
