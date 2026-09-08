package org.pqcfuzz.target.jdk;

import org.pqcfuzz.classify.ExpectedRejections;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;
import org.pqcfuzz.target.mlkem.MlKemKeys;

import java.security.KeyFactory;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code KeyFactory.generatePublic(X509EncodedKeySpec)} in the JDK's {@code SunJCE} ML-KEM-768: the
 * decoder a server runs on the client's key share. The fuzzed input is the raw 1184-byte key; the
 * SubjectPublicKeyInfo wrapper is regenerated around it (see {@link JdkPqc}). The seed corpus is the
 * same set of BouncyCastle-derived keys the {@code ml-kem-768-pubkey-parse} target uses.
 */
public final class JdkMlKem768PublicKeyParseTarget implements FuzzTarget {

    private static final int SEED_KEYS = 4;

    private final KeyFactory factory = JdkPqc.keyFactory("ML-KEM-768");
    private final List<byte[]> seeds;
    private final int encodedLength;

    public JdkMlKem768PublicKeyParseTarget(long seed) {
        List<byte[]> corpus = new ArrayList<>(SEED_KEYS);
        for (int i = 0; i < SEED_KEYS; i++) {
            corpus.add(new MlKemKeys(seed + i).publicKey.getEncoded());
        }
        this.seeds = List.copyOf(corpus);
        this.encodedLength = corpus.get(0).length;
    }

    @Override
    public String name() {
        return "jdk-ml-kem-768-pubkey-parse";
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
        return JdkPqc.parse(factory, JdkPqc.OID_ML_KEM_768, input) != null;
    }

    @Override
    public boolean isDocumentedRejection(Throwable t) {
        return ExpectedRejections.isDocumentedJdkRejection(t);
    }
}
