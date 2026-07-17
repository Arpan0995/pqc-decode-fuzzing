package org.pqcfuzz.target.slhdsa;

import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * SLH-DSA-SHA2-128f <em>parse then verify</em>: decode an attacker-supplied public key and verify a
 * signature with it. The fuzzed input is the <b>key encoding</b>.
 *
 * <p>The counterpart to {@link org.pqcfuzz.target.mldsa.MlDsa65ParseAndVerifyTarget}, and a useful
 * comparison against it: SLH-DSA's decoder does enforce its 32-byte length, so if the composed path is
 * robust here but not for ML-DSA, the difference is attributable to that check rather than to anything
 * about verification.
 */
public final class SlhDsaParseAndVerifyTarget implements FuzzTarget {

    private static final int WRONG_KEY_SEEDS = 2;

    private final byte[] message;
    private final byte[] signature;
    private final byte[] genuineKey;
    private final List<byte[]> seeds;

    public SlhDsaParseAndVerifyTarget(long seed) {
        SlhDsaKeys keys = new SlhDsaKeys(seed);
        this.message = ("pqc-decode-fuzzing slh-dsa-sha2-128f parse-verify target, seed=" + seed)
                .getBytes(StandardCharsets.UTF_8);
        this.signature = keys.sign(message);
        this.genuineKey = keys.publicKey.getEncoded();

        List<byte[]> corpus = new ArrayList<>(1 + WRONG_KEY_SEEDS);
        corpus.add(genuineKey);
        for (int i = 1; i <= WRONG_KEY_SEEDS; i++) {
            corpus.add(new SlhDsaKeys(seed + i).publicKey.getEncoded());
        }
        this.seeds = List.copyOf(corpus);
    }

    @Override
    public String name() {
        return "slh-dsa-sha2-128f-parse-verify";
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
    public boolean accepts(byte[] input) {
        SLHDSAPublicKeyParameters publicKey =
                new SLHDSAPublicKeyParameters(SlhDsaKeys.PARAMETERS, input);
        SLHDSASigner verifier = new SLHDSASigner();
        verifier.init(false, publicKey);
        return verifier.verifySignature(message, signature);
    }
}
