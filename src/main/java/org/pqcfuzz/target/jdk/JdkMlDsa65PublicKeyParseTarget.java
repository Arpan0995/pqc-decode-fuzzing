package org.pqcfuzz.target.jdk;

import org.pqcfuzz.classify.ExpectedRejections;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;
import org.pqcfuzz.target.mldsa.MlDsaKeys;

import java.security.KeyFactory;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code KeyFactory.generatePublic(X509EncodedKeySpec)} in the JDK's {@code SUN} ML-DSA-65: the
 * decoder that {@code CertificateFactory} runs on the key in a peer's certificate. The fuzzed input
 * is the raw 1952-byte key, wrapped as described in {@link JdkPqc}; the seed corpus is the same set
 * of BouncyCastle-derived keys that {@code ml-dsa-65-pubkey-parse} uses.
 */
public final class JdkMlDsa65PublicKeyParseTarget implements FuzzTarget {

    private static final int SEED_KEYS = 4;

    private final KeyFactory factory = JdkPqc.keyFactory("ML-DSA-65");
    private final List<byte[]> seeds;
    private final int encodedLength;

    public JdkMlDsa65PublicKeyParseTarget(long seed) {
        byte[][] corpus = new byte[SEED_KEYS][];
        for (int i = 0; i < SEED_KEYS; i++) {
            corpus[i] = new MlDsaKeys(seed + i).publicKey.getEncoded();
        }
        this.seeds = List.of(corpus);
        this.encodedLength = corpus[0].length;
    }

    @Override
    public String name() {
        return "jdk-ml-dsa-65-pubkey-parse";
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
        return JdkPqc.parse(factory, JdkPqc.OID_ML_DSA_65, input) != null;
    }

    @Override
    public boolean isDocumentedRejection(Throwable t) {
        return ExpectedRejections.isDocumentedJdkRejection(t);
    }
}
