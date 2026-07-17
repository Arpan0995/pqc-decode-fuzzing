package org.pqcfuzz.target.mldsa;

import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * ML-DSA-65 <em>parse then verify</em>: decode an attacker-supplied public key and verify a signature
 * with it. The fuzzed input is the <b>key encoding</b>, not the signature.
 *
 * <p>This is the certificate path, and it exists because the defect it catches lives in the seam
 * between two functions that are each individually fine. Parsing a malformed key looks harmless — the
 * constructor returns an object and throws nothing. Verifying with a well-formed key is likewise
 * robust. Only the composition fails, and it is the composition that every TLS client performs: parse
 * the key out of the peer's certificate, then use it.
 *
 * <p>Fuzzing the two entry points separately provably misses this. In BouncyCastle 1.84,
 * {@code MLDSAPublicKeyParameters} accepts any encoding of 33 bytes or more with no length check, so a
 * parse-only target records a contented {@code OK}; the {@code ArrayIndexOutOfBoundsException} only
 * arrives once the resulting key is handed to a signer. A study that fuzzed only the pre-registered
 * six would have reported the library clean on precisely the input that breaks it.
 */
public final class MlDsa65ParseAndVerifyTarget implements FuzzTarget {

    private static final int WRONG_KEY_SEEDS = 3;

    private final byte[] message;
    private final byte[] signature;
    private final byte[] genuineKey;
    private final List<byte[]> seeds;

    public MlDsa65ParseAndVerifyTarget(long seed) {
        MlDsaKeys keys = new MlDsaKeys(seed);
        this.message = ("pqc-decode-fuzzing ml-dsa-65 parse-verify target, seed=" + seed)
                .getBytes(StandardCharsets.UTF_8);
        this.signature = keys.sign(message);
        this.genuineKey = keys.publicKey.getEncoded();

        List<byte[]> corpus = new ArrayList<>(1 + WRONG_KEY_SEEDS);
        corpus.add(genuineKey);
        for (int i = 1; i <= WRONG_KEY_SEEDS; i++) {
            corpus.add(new MlDsaKeys(seed + i).publicKey.getEncoded());
        }
        this.seeds = List.copyOf(corpus);
    }

    @Override
    public String name() {
        return "ml-dsa-65-parse-verify";
    }

    /**
     * Held to the verify contract, since that is what the composed operation claims. Only the genuine
     * key may verify this signature: a mutated key that verified it would mean the signature is
     * accepted under a key that never signed it, which is a break rather than a parsing quirk.
     */
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
        MLDSAPublicKeyParameters publicKey =
                new MLDSAPublicKeyParameters(MlDsaKeys.PARAMETERS, input);
        MLDSASigner verifier = new MLDSASigner();
        verifier.init(false, publicKey);
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signature);
    }
}
