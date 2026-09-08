package org.pqcfuzz.target.jdk;

import org.pqcfuzz.classify.ExpectedRejections;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.util.ArrayList;
import java.util.List;

/**
 * {@code KEM.Decapsulator.decapsulate(byte[])} in the JDK's {@code SunJCE} ML-KEM-768: the server-side
 * function that consumes the client's ciphertext. Same contract as {@code ml-kem-768-decap}: a
 * correct-length input never throws (implicit rejection returns a secret), other input rejects with
 * the documented {@code DecapsulateException}.
 */
public final class JdkMlKem768DecapTarget implements FuzzTarget {

    private static final int SEED_CIPHERTEXTS = 4;

    private final JdkMlKemKeys keys;
    private final List<byte[]> seeds;
    private final int encapsulationLength;

    public JdkMlKem768DecapTarget(long seed) {
        this.keys = new JdkMlKemKeys(seed);
        List<byte[]> corpus = new ArrayList<>(SEED_CIPHERTEXTS);
        for (int i = 0; i < SEED_CIPHERTEXTS; i++) {
            corpus.add(keys.encapsulate());
        }
        this.seeds = List.copyOf(corpus);
        this.encapsulationLength = corpus.get(0).length;
    }

    @Override
    public String name() {
        return "jdk-ml-kem-768-decap";
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

    @Override
    public boolean accepts(byte[] input) throws Exception {
        return keys.decapsulator.decapsulate(input) != null;
    }

    @Override
    public boolean isDocumentedRejection(Throwable t) {
        return ExpectedRejections.isDocumentedJdkRejection(t);
    }
}
