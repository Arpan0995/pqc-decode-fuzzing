package org.pqcfuzz.target.slhdsa;

import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * SLH-DSA-SHA2-128f signature verification: {@code SLHDSASigner.verifySignature(byte[], byte[])} over a
 * fixed message.
 *
 * <p>The most structurally intricate verify path in this study. Where ML-DSA verification decodes a
 * handful of packed vectors, SLH-DSA verification walks a hypertree — reconstructing a FORS root and
 * then a chain of WOTS+ signatures and Merkle authentication paths, each carved out of the 17088-byte
 * signature at computed offsets. Offsets computed from attacker-supplied bytes are exactly where
 * bounds mistakes live, which makes this the target most likely to answer RQ2 with something.
 *
 * <p>Unlike {@code MLDSASigner}, {@code SLHDSASigner} takes the message and signature together and
 * holds no per-message state, so one verifier instance is safely reused across inputs.
 */
public final class SlhDsaVerifyTarget implements FuzzTarget {

    private static final int WRONG_KEY_SEEDS = 2;

    private final byte[] message;
    private final byte[] genuineSignature;
    private final List<byte[]> seeds;
    private final SLHDSASigner verifier;

    public SlhDsaVerifyTarget(long seed) {
        SlhDsaKeys keys = new SlhDsaKeys(seed);
        this.message = ("pqc-decode-fuzzing slh-dsa-sha2-128f verify target, seed=" + seed)
                .getBytes(StandardCharsets.UTF_8);
        this.genuineSignature = keys.sign(message);

        List<byte[]> corpus = new ArrayList<>(1 + WRONG_KEY_SEEDS);
        corpus.add(genuineSignature);
        for (int i = 1; i <= WRONG_KEY_SEEDS; i++) {
            corpus.add(new SlhDsaKeys(seed + i).sign(message));
        }
        this.seeds = List.copyOf(corpus);

        this.verifier = new SLHDSASigner();
        this.verifier.init(false, keys.publicKey);
    }

    @Override
    public String name() {
        return "slh-dsa-sha2-128f-verify";
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
    public boolean accepts(byte[] input) {
        return verifier.verifySignature(message, input);
    }
}
