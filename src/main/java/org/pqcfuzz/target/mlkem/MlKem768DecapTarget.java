package org.pqcfuzz.target.mlkem;

import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.util.ArrayList;
import java.util.List;

/**
 * ML-KEM-768 decapsulation: {@code MLKEMExtractor.extractSecret(byte[])}.
 *
 * <p>This is the entry point a TLS server reaches with a ciphertext chosen entirely by the client, so
 * its robustness is availability-critical. It is also the one target with no notion of rejection: under
 * the Fujisaki–Okamoto transform a correct-length ciphertext <em>always</em> produces a secret — the
 * real one if the ciphertext is genuine, a pseudorandom implicit-rejection value if it is not. The
 * caller cannot tell, and that is by design.
 *
 * <p>The pre-registered expectation (H3) is therefore sharp: for a correct-length (1088-byte) input,
 * {@code extractSecret} must never throw, no matter how corrupt the ciphertext is. Wrong-length inputs
 * carry no such guarantee and are expected to throw — the question is whether they throw a
 * <em>documented</em> exception.
 */
public final class MlKem768DecapTarget implements FuzzTarget {

    private static final int SEED_CIPHERTEXTS = 4;

    private final MlKemKeys keys;
    private final List<byte[]> seeds;
    private final int encapsulationLength;

    public MlKem768DecapTarget(long seed) {
        this.keys = new MlKemKeys(seed);
        this.encapsulationLength = keys.extractor.getEncapsulationLength();
        List<byte[]> corpus = new ArrayList<>(SEED_CIPHERTEXTS);
        for (int i = 0; i < SEED_CIPHERTEXTS; i++) {
            corpus.add(keys.encapsulate().getEncapsulation());
        }
        this.seeds = List.copyOf(corpus);
    }

    @Override
    public String name() {
        return "ml-kem-768-decap";
    }

    @Override
    public TargetKind kind() {
        return TargetKind.DECAPSULATE;
    }

    @Override
    public List<byte[]> seedCorpus() {
        return seeds;
    }

    @Override
    public int nominalInputLength() {
        return encapsulationLength;
    }

    /**
     * Always reports "accepted" when the call returns, since decapsulation has no reject signal: a
     * returned secret carries no claim that the ciphertext was genuine. Only a throw or a hang is a
     * finding here.
     */
    @Override
    public boolean accepts(byte[] input) {
        byte[] secret = keys.extractor.extractSecret(input);
        return secret != null;
    }
}
