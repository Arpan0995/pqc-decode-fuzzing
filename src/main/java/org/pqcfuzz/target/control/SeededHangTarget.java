package org.pqcfuzz.target.control;

import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;
import org.pqcfuzz.target.mldsa.MlDsaKeys;

import java.util.List;

/**
 * A synthetic hang control (design amendment A7): the ML-DSA-65 public-key decoder of the library
 * under test, followed by a planted computation that does not return within the campaign's per-input
 * budget, and that runs only when the same {@code k}-bit guard as {@link SeededGuardTarget} is
 * satisfied.
 *
 * <p>Both other controls end in an exception. Until this target existed nothing in the study had shown
 * that the watchdog scores a hang, so H4 ("no input hangs") rested on an instrument never seen to
 * detect one. Behind the same guard, at the same byte offset, this target spins for
 * {@value #SPIN_SECONDS} seconds instead of throwing. Because the guard, the genuine key and the
 * mutation stream are identical for a given seed and width, a campaign reaches this fault on exactly
 * the inputs on which it reached the exception fault, so the two controls can be compared position by
 * position.
 *
 * <p>The spin is a busy loop that does not check interrupts, which is how a genuine algorithmic
 * blow-up inside library code behaves; the campaign's watchdog abandons the thread and moves on. Like
 * the exception control it is synthetic, labelled so wherever it is reported, and never part of a
 * campaign whose result is read as evidence about a library.
 */
public final class SeededHangTarget implements FuzzTarget {

    /** Name prefix; the suffix is the number of guarded bits. */
    public static final String PREFIX = "seeded-hang-k";

    /** Byte offset of the guarded bits, the same as the exception control's. */
    static final int OFFSET = SeededGuardTarget.OFFSET;

    /** How long the planted fault spins, well past any per-input budget the campaign uses. */
    static final long SPIN_SECONDS = 20;

    private final int bits;
    private final byte[] genuine;
    private final long want;
    private final long mask;

    public SeededHangTarget(int bits, long seed) {
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
            long deadline = System.nanoTime() + SPIN_SECONDS * 1_000_000_000L;
            while (System.nanoTime() < deadline) {
                Thread.onSpinWait();
            }
        }
        return parsed.getEncoded() != null;
    }
}
