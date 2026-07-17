package org.pqcfuzz.target.slhdsa;

import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.util.List;

/**
 * SLH-DSA-SHA2-128f public-key parsing: {@code new SLHDSAPublicKeyParameters(params, byte[])}.
 *
 * <p>The smallest input in the study: a 32-byte key, being a 16-byte public seed and a 16-byte hypertree
 * root. With so little structure there is little for a parser to get wrong beyond the length check
 * itself — which makes this a useful control on the other decoders. If a 32-byte decoder and a
 * 1952-byte decoder both reject cleanly, the length check is the whole story; if only the small one
 * does, the difference is in the unpacking.
 */
public final class SlhDsaPublicKeyParseTarget implements FuzzTarget {

    private static final int SEED_KEYS = 4;

    private final List<byte[]> seeds;
    private final int encodedLength;

    public SlhDsaPublicKeyParseTarget(long seed) {
        byte[][] corpus = new byte[SEED_KEYS][];
        for (int i = 0; i < SEED_KEYS; i++) {
            corpus[i] = new SlhDsaKeys(seed + i).publicKey.getEncoded();
        }
        this.seeds = List.of(corpus);
        this.encodedLength = corpus[0].length;
    }

    @Override
    public String name() {
        return "slh-dsa-sha2-128f-pubkey-parse";
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
        SLHDSAPublicKeyParameters parsed = new SLHDSAPublicKeyParameters(SlhDsaKeys.PARAMETERS, input);
        return parsed.getEncoded() != null;
    }
}
