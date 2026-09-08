package org.pqcfuzz.target.jdk;

import org.pqcfuzz.classify.ExpectedRejections;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code Signature.verify(byte[])} in the JDK's {@code SUN} ML-DSA-65: the client-side function that
 * consumes the server's signature. The message and the seed corpus (one genuine signature, three
 * made with other keys) are byte-for-byte those of {@code ml-dsa-65-verify}, because the key pair and
 * the deterministic signer are shared (see {@link JdkMlDsaKeys}).
 *
 * <p>The JDK's documented policy differs from BouncyCastle's in one respect: a structurally malformed
 * signature <em>throws</em> {@code SignatureException} where BouncyCastle returns false. Both are
 * documented rejections; the classifier scores both {@code REJECTED}.
 */
public final class JdkMlDsa65VerifyTarget implements FuzzTarget {

    private static final int WRONG_KEY_SEEDS = 3;

    private final KeyFactory factory = JdkPqc.keyFactory("ML-DSA-65");
    private final JdkMlDsaKeys keys;
    private final byte[] message;
    private final byte[] genuineSignature;
    private final List<byte[]> seeds;
    private Signature verifier;

    public JdkMlDsa65VerifyTarget(long seed) {
        this.keys = new JdkMlDsaKeys(seed, factory);
        this.message = ("pqc-decode-fuzzing ml-dsa-65 verify target, seed=" + seed)
                .getBytes(StandardCharsets.UTF_8);
        this.genuineSignature = keys.sign(message);
        List<byte[]> corpus = new ArrayList<>(1 + WRONG_KEY_SEEDS);
        corpus.add(genuineSignature);
        for (int i = 1; i <= WRONG_KEY_SEEDS; i++) {
            corpus.add(new JdkMlDsaKeys(seed + i, factory).sign(message));
        }
        this.seeds = List.copyOf(corpus);
    }

    @Override
    public String name() {
        return "jdk-ml-dsa-65-verify";
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
        return List.of(genuineSignature);
    }

    @Override
    public int nominalInputLength() {
        return genuineSignature.length;
    }

    @Override
    public boolean accepts(byte[] input) throws Exception {
        Signature v = verifier();
        try {
            v.update(message);
            return v.verify(input);
        } catch (Throwable t) {
            // Same discipline as the BouncyCastle target: never let one input's failure leave state
            // behind that could manufacture an anomaly on the next one.
            verifier = null;
            throw t;
        }
    }

    private Signature verifier() throws Exception {
        if (verifier == null) {
            Signature v = Signature.getInstance("ML-DSA-65");
            v.initVerify(keys.publicKey);
            verifier = v;
        }
        return verifier;
    }

    @Override
    public boolean isDocumentedRejection(Throwable t) {
        return ExpectedRejections.isDocumentedJdkRejection(t);
    }
}
