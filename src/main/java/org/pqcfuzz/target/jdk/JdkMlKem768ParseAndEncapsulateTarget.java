package org.pqcfuzz.target.jdk;

import org.pqcfuzz.classify.ExpectedRejections;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;
import org.pqcfuzz.target.mlkem.MlKemKeys;
import org.pqcfuzz.util.DeterministicSecureRandom;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KEM;

/**
 * The composed server path in the JDK: parse the client's key share with {@code KeyFactory}, then
 * hand the result to {@code KEM.newEncapsulator} and encapsulate. The fuzzed input is the raw key.
 * A defect in the seam between the two calls, a key the decoder accepts but the encapsulator cannot
 * use, is exactly what the BouncyCastle 1.84 control looked like.
 */
public final class JdkMlKem768ParseAndEncapsulateTarget implements FuzzTarget {

    private static final int SEED_KEYS = 4;

    private final KeyFactory factory = JdkPqc.keyFactory("ML-KEM-768");
    private final KEM kem = JdkPqc.kem("ML-KEM-768");
    private final SecureRandom random;
    private final List<byte[]> seeds;
    private final int encodedLength;

    public JdkMlKem768ParseAndEncapsulateTarget(long seed) {
        List<byte[]> corpus = new ArrayList<>(SEED_KEYS);
        for (int i = 0; i < SEED_KEYS; i++) {
            corpus.add(new MlKemKeys(seed + i).publicKey.getEncoded());
        }
        this.seeds = List.copyOf(corpus);
        this.encodedLength = corpus.get(0).length;
        // Encapsulation consumes randomness; seed it so the campaign stays replayable.
        this.random = new DeterministicSecureRandom(seed ^ 0x0F0F_F0F0L);
    }

    @Override
    public String name() {
        return "jdk-ml-kem-768-parse-encapsulate";
    }

    @Override
    public TargetKind kind() {
        return TargetKind.DECODE;
    }

    @Override
    public List<byte[]> seedCorpus() {
        return seeds;
    }

    @Override
    public int nominalInputLength() {
        return encodedLength;
    }

    @Override
    public boolean accepts(byte[] input) throws Exception {
        PublicKey publicKey = JdkPqc.parse(factory, JdkPqc.OID_ML_KEM_768, input);
        return kem.newEncapsulator(publicKey, random).encapsulate().encapsulation() != null;
    }

    @Override
    public boolean isDocumentedRejection(Throwable t) {
        return ExpectedRejections.isDocumentedJdkRejection(t);
    }
}
