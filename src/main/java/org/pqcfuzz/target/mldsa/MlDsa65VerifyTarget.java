package org.pqcfuzz.target.mldsa;

import org.bouncycastle.crypto.signers.MLDSASigner;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * ML-DSA-65 signature verification: {@code MLDSASigner.verifySignature(byte[])} over a fixed message.
 *
 * <p>The message is held fixed and the signature is fuzzed, which mirrors the threat: a client
 * verifying a server's signature over a transcript it already knows, with the signature bytes supplied
 * by whoever is on the other end of the connection. Verification must be a <em>total</em> function of
 * those bytes — true, or false, never an exception and never a hang (H1).
 *
 * <p>The seed corpus includes signatures made with <em>other</em> keys over the same message. These are
 * not forgeries to be found but material to mutate: they are structurally perfect signatures that fail
 * only at the final check, so they drive verification through its full decode path rather than tripping
 * an early length test. Only {@link #genuineInputs()} may legitimately verify.
 */
public final class MlDsa65VerifyTarget implements FuzzTarget {

    private static final int WRONG_KEY_SEEDS = 3;

    private final MlDsaKeys keys;
    private final byte[] message;
    private final byte[] genuineSignature;
    private final List<byte[]> seeds;

    /** Reused across inputs to avoid re-expanding the public key; discarded if an input dirties it. */
    private MLDSASigner verifier;

    public MlDsa65VerifyTarget(long seed) {
        this.keys = new MlDsaKeys(seed);
        this.message = ("pqc-decode-fuzzing ml-dsa-65 verify target, seed=" + seed)
                .getBytes(StandardCharsets.UTF_8);
        this.genuineSignature = keys.sign(message);

        List<byte[]> corpus = new ArrayList<>(1 + WRONG_KEY_SEEDS);
        corpus.add(genuineSignature);
        for (int i = 1; i <= WRONG_KEY_SEEDS; i++) {
            corpus.add(new MlDsaKeys(seed + i).sign(message));
        }
        this.seeds = List.copyOf(corpus);
    }

    @Override
    public String name() {
        return "ml-dsa-65-verify";
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
        MLDSASigner v = verifier();
        try {
            v.reset();
            v.update(message, 0, message.length);
            return v.verifySignature(input);
        } catch (Throwable t) {
            // An input that threw part-way through may have left the signer's digest state dirty.
            // Reusing it could make the *next* input fail for reasons of our own making, manufacturing
            // anomalies that are artefacts of the harness rather than defects in the library. Drop it.
            verifier = null;
            throw t;
        }
    }

    private MLDSASigner verifier() {
        if (verifier == null) {
            MLDSASigner v = new MLDSASigner();
            v.init(false, keys.publicKey);
            verifier = v;
        }
        return verifier;
    }
}
