package org.pqcfuzz.target.control;

import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;
import org.pqcfuzz.target.mldsa.MlDsaKeys;

import java.util.List;

/**
 * A synthetic, graded control (design amendment A6): the ML-DSA-65 public-key decoder of the library
 * under test, followed by one planted fault that fires only when {@code k} chosen bits of the input
 * hold a chosen value.
 *
 * <p>The real control (BouncyCastle 1.84) shows the instrument can see a defect that a quarter of all
 * inputs reach. It cannot show how rare a defect the instrument could still see. This target can: the
 * planted fault sits behind the real decoder, so an input must first have the right length and parse,
 * and it then fires only if the {@code k} bits starting at byte {@value #OFFSET} equal the complement
 * of the genuine key's bits there. Raising {@code k} makes the same fault harder to reach without
 * changing anything else, which turns "could the campaign have found it" into a measured curve.
 *
 * <p>The fault is an {@link ArrayIndexOutOfBoundsException}, the exception the real control throws,
 * so the classifier scores it exactly as it scored the real defect. The design follows the
 * magic-value faults that LAVA plants; it is labelled synthetic everywhere it is reported, and it is
 * never part of a campaign whose result is read as evidence about a library.
 */
public final class SeededGuardTarget implements FuzzTarget {

    /** Name prefix; the suffix is the number of guarded bits. */
    public static final String PREFIX = "seeded-guard-k";

    /** Byte offset of the guarded bits, inside the packed t1 vector of the key. */
    static final int OFFSET = 1000;

    private final int bits;
    private final byte[] genuine;
    private final long want;
    private final long mask;

    public SeededGuardTarget(int bits, long seed) {
        if (bits < 1 || bits > 64) {
            throw new IllegalArgumentException("guarded bits must be between 1 and 64, got " + bits);
        }
        this.bits = bits;
        this.genuine = new MlDsaKeys(seed).publicKey.getEncoded();
        this.mask = bits == 64 ? -1L : (1L << bits) - 1;
        this.want = ~window(genuine) & mask;
    }

    /** The {@code bits} bits starting at {@link #OFFSET}, most significant first, as one number. */
    private long window(byte[] encoding) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (encoding[OFFSET + i] & 0xFFL);
        }
        return (value >>> (64 - bits)) & mask;
    }

    @Override
    public String name() {
        return PREFIX + bits;
    }

    @Override
    public TargetKind kind() {
        return TargetKind.DECODE;
    }

    @Override
    public List<byte[]> seedCorpus() {
        return List.of(genuine);
    }

    @Override
    public int nominalInputLength() {
        return genuine.length;
    }

    @Override
    public boolean accepts(byte[] input) {
        MLDSAPublicKeyParameters parsed = new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, input);
        if (input.length == genuine.length && window(input) == want) {
            throw new ArrayIndexOutOfBoundsException("seeded control fault behind a " + bits + "-bit guard");
        }
        return parsed.getEncoded() != null;
    }
}
