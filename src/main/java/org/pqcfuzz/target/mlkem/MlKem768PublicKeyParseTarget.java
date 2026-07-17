package org.pqcfuzz.target.mlkem;

import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.util.List;

/**
 * ML-KEM-768 public-key parsing: {@code new MLKEMPublicKeyParameters(params, byte[])}.
 *
 * <p>Reached whenever a peer's key share or certificate is decoded, on bytes the peer chose. An
 * ML-KEM-768 encoded key is 1184 bytes: 1152 bytes of packed polynomial coefficients plus a 32-byte
 * rho. Malformed input should draw a documented exception, not a bounds violation.
 */
public final class MlKem768PublicKeyParseTarget implements FuzzTarget {

    private static final int SEED_KEYS = 4;

    private final List<byte[]> seeds;
    private final int encodedLength;

    public MlKem768PublicKeyParseTarget(long seed) {
        byte[][] corpus = new byte[SEED_KEYS][];
        for (int i = 0; i < SEED_KEYS; i++) {
            corpus[i] = new MlKemKeys(seed + i).publicKey.getEncoded();
        }
        this.seeds = List.of(corpus);
        this.encodedLength = corpus[0].length;
    }

    @Override
    public String name() {
        return "ml-kem-768-pubkey-parse";
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
        MLKEMPublicKeyParameters parsed = new MLKEMPublicKeyParameters(MlKemKeys.PARAMETERS, input);
        return parsed.getEncoded() != null;
    }
}
