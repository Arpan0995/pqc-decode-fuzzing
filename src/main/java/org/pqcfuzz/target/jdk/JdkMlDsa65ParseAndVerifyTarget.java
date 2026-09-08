package org.pqcfuzz.target.jdk;

import org.pqcfuzz.classify.ExpectedRejections;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

/**
 * The composed client path in the JDK: parse the key from the server's certificate with
 * {@code KeyFactory}, then {@code Signature.initVerify} with it and verify a genuine signature. The
 * fuzzed input is the raw key. The message, the signature and the seed keys are byte-for-byte those
 * of {@code ml-dsa-65-parse-verify} (see {@link JdkMlDsaKeys}).
 */
public final class JdkMlDsa65ParseAndVerifyTarget implements FuzzTarget {

    private static final int WRONG_KEY_SEEDS = 3;

    private final KeyFactory factory = JdkPqc.keyFactory("ML-DSA-65");
    private final byte[] message;
    private final byte[] signature;
    private final byte[] genuineKey;
    private final List<byte[]> seeds;

    public JdkMlDsa65ParseAndVerifyTarget(long seed) {
        JdkMlDsaKeys keys = new JdkMlDsaKeys(seed, factory);
        this.message = ("pqc-decode-fuzzing ml-dsa-65 parse-verify target, seed=" + seed)
                .getBytes(StandardCharsets.UTF_8);
        this.signature = keys.sign(message);
        this.genuineKey = keys.rawPublicKey;
        List<byte[]> corpus = new ArrayList<>(1 + WRONG_KEY_SEEDS);
        corpus.add(genuineKey);
        for (int i = 1; i <= WRONG_KEY_SEEDS; i++) {
            corpus.add(new JdkMlDsaKeys(seed + i, factory).rawPublicKey);
        }
        this.seeds = List.copyOf(corpus);
    }

    @Override
    public String name() {
        return "jdk-ml-dsa-65-parse-verify";
    }

    @Override
    public TargetKind kind() {
        return TargetKind.VERIFY;
    }

    @Override
    public List<byte[]> seedCorpus() {
        return seeds;
    }

    @Override
    public List<byte[]> genuineInputs() {
        return List.of(genuineKey);
    }

    @Override
    public int nominalInputLength() {
        return genuineKey.length;
    }

    @Override
    public boolean accepts(byte[] input) throws Exception {
        PublicKey publicKey = JdkPqc.parse(factory, JdkPqc.OID_ML_DSA_65, input);
        Signature verifier = Signature.getInstance("ML-DSA-65");
        verifier.initVerify(publicKey);
        verifier.update(message);
        return verifier.verify(signature);
    }

    @Override
    public boolean isDocumentedRejection(Throwable t) {
        return ExpectedRejections.isDocumentedJdkRejection(t);
    }
}
