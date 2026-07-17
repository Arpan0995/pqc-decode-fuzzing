package org.pqcfuzz.target.mldsa;

import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.util.List;

/**
 * ML-DSA-65 public-key parsing: {@code new MLDSAPublicKeyParameters(params, byte[])}.
 *
 * <p>Reached when decoding a peer's certificate. An ML-DSA-65 encoded key is 1952 bytes: a 32-byte rho
 * followed by the packed t1 vector. Malformed input should draw a documented exception.
 */
public final class MlDsa65PublicKeyParseTarget implements FuzzTarget {

    private static final int SEED_KEYS = 4;

    private final List<byte[]> seeds;
    private final int encodedLength;

    public MlDsa65PublicKeyParseTarget(long seed) {
        byte[][] corpus = new byte[SEED_KEYS][];
        for (int i = 0; i < SEED_KEYS; i++) {
            corpus[i] = new MlDsaKeys(seed + i).publicKey.getEncoded();
        }
        this.seeds = List.of(corpus);
        this.encodedLength = corpus[0].length;
    }

    @Override
    public String name() {
        return "ml-dsa-65-pubkey-parse";
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
    public boolean accepts(byte[] input) {
        MLDSAPublicKeyParameters parsed = new MLDSAPublicKeyParameters(MlDsaKeys.PARAMETERS, input);
        return parsed.getEncoded() != null;
    }
}
