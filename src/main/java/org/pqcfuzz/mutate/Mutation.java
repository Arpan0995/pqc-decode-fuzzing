package org.pqcfuzz.mutate;

import java.util.random.RandomGenerator;

/**
 * The structured mutation strategies applied to valid seed encodings (design §5). Each takes a
 * well-formed input and damages it in one characteristic way; recording the outcome per strategy shows
 * <em>which kind</em> of malformation reaches a defect, not merely that one exists.
 *
 * <p>The strategies split into two families. {@link #BIT_FLIP} through {@link #CHUNK_RANDOMIZE} keep the
 * length correct and corrupt the <em>contents</em>, probing the unpacking and arithmetic that runs once
 * a length check has passed. {@link #TRUNCATE} through {@link #LENGTH_EDGE} attack the <em>length</em>
 * itself, probing the bounds checks. The content family is where a total-function violation would show
 * up in verification; the length family is where decoders classically go wrong.
 *
 * <p>Every strategy is a pure function of its seed and {@link RandomGenerator}, so a campaign replays
 * exactly from its seed.
 */
public enum Mutation {

    /** Flip one bit. The minimal perturbation: the input stays a valid length and is almost genuine. */
    BIT_FLIP {
        @Override
        public byte[] apply(byte[] seed, int nominalLength, RandomGenerator rng) {
            byte[] out = seed.clone();
            if (out.length == 0) {
                return out;
            }
            flipRandomBit(out, rng);
            return out;
        }
    },

    /** Flip 2–8 bits, scattered. Past the point where a single flip might land somewhere inert. */
    MULTI_BIT_FLIP {
        @Override
        public byte[] apply(byte[] seed, int nominalLength, RandomGenerator rng) {
            byte[] out = seed.clone();
            if (out.length == 0) {
                return out;
            }
            int flips = 2 + rng.nextInt(7);
            for (int i = 0; i < flips; i++) {
                flipRandomBit(out, rng);
            }
            return out;
        }
    },

    /** Replace one byte with a random value — a coarser jump than a bit flip. */
    BYTE_SUBSTITUTE {
        @Override
        public byte[] apply(byte[] seed, int nominalLength, RandomGenerator rng) {
            byte[] out = seed.clone();
            if (out.length == 0) {
                return out;
            }
            out[rng.nextInt(out.length)] = (byte) rng.nextInt(256);
            return out;
        }
    },

    /**
     * Randomize a contiguous span of up to 64 bytes. Targets structure rather than a scalar: in a
     * signature this can wipe out a whole WOTS+ chain or a packed coefficient block while leaving the
     * rest genuine, so the decoder reaches that component through an otherwise valid parse.
     */
    CHUNK_RANDOMIZE {
        @Override
        public byte[] apply(byte[] seed, int nominalLength, RandomGenerator rng) {
            byte[] out = seed.clone();
            if (out.length == 0) {
                return out;
            }
            int span = 1 + rng.nextInt(Math.min(64, out.length));
            int start = rng.nextInt(out.length - span + 1);
            for (int i = start; i < start + span; i++) {
                out[i] = (byte) rng.nextInt(256);
            }
            return out;
        }
    },

    /** Cut the input short at a random point — the classic way to walk a parser off the end. */
    TRUNCATE {
        @Override
        public byte[] apply(byte[] seed, int nominalLength, RandomGenerator rng) {
            if (seed.length == 0) {
                return seed.clone();
            }
            int keep = rng.nextInt(seed.length);
            byte[] out = new byte[keep];
            System.arraycopy(seed, 0, out, 0, keep);
            return out;
        }
    },

    /** Append random trailing bytes: does the target notice, or read past what it should? */
    EXTEND {
        @Override
        public byte[] apply(byte[] seed, int nominalLength, RandomGenerator rng) {
            int extra = 1 + rng.nextInt(Math.max(1, nominalLength));
            byte[] out = new byte[seed.length + extra];
            System.arraycopy(seed, 0, out, 0, seed.length);
            for (int i = seed.length; i < out.length; i++) {
                out[i] = (byte) rng.nextInt(256);
            }
            return out;
        }
    },

    /** All zero bytes at the nominal length — a degenerate but perfectly sized input. */
    ZERO_FILL {
        @Override
        public byte[] apply(byte[] seed, int nominalLength, RandomGenerator rng) {
            return new byte[nominalLength];
        }
    },

    /**
     * All 0xFF bytes at the nominal length. The counterpart to {@link #ZERO_FILL} and the more
     * interesting of the two: where a packed field is read as an integer, all-ones is the value most
     * likely to overflow it or index off the end of a lookup.
     */
    ONES_FILL {
        @Override
        public byte[] apply(byte[] seed, int nominalLength, RandomGenerator rng) {
            byte[] out = new byte[nominalLength];
            java.util.Arrays.fill(out, (byte) 0xFF);
            return out;
        }
    },

    /**
     * Boundary lengths, uniformly chosen: empty, one byte, one short, one long, double, and 1 MiB.
     *
     * <p>These fixed-length encodings carry no length field to corrupt, so the length <em>is</em> the
     * field: the wire format says "1184 bytes" and the only thing an attacker can lie about is how many
     * bytes they actually send. Off-by-one is where a bounds check is either right or wrong, and the
     * 1 MiB case asks whether an oversized input is rejected on sight or copied first.
     */
    LENGTH_EDGE {
        @Override
        public byte[] apply(byte[] seed, int nominalLength, RandomGenerator rng) {
            int[] lengths = {
                0, 1, Math.max(0, nominalLength - 1), nominalLength + 1, nominalLength * 2, 1 << 20
            };
            int length = lengths[rng.nextInt(lengths.length)];
            byte[] out = new byte[length];
            int copy = Math.min(seed.length, length);
            System.arraycopy(seed, 0, out, 0, copy);
            for (int i = copy; i < length; i++) {
                out[i] = (byte) rng.nextInt(256);
            }
            return out;
        }
    },

    /** Uniform random bytes at the nominal length, ignoring the seed — no structure at all. */
    RANDOM {
        @Override
        public byte[] apply(byte[] seed, int nominalLength, RandomGenerator rng) {
            byte[] out = new byte[nominalLength];
            rng.nextBytes(out);
            return out;
        }
    };

    /**
     * Produce one mutated input.
     *
     * @param seed a well-formed input to damage; never modified
     * @param nominalLength the length of a well-formed input for this target
     * @return a fresh array, which may be of any length
     */
    public abstract byte[] apply(byte[] seed, int nominalLength, RandomGenerator rng);

    private static void flipRandomBit(byte[] buf, RandomGenerator rng) {
        int bit = rng.nextInt(buf.length * 8);
        buf[bit >>> 3] ^= (byte) (1 << (bit & 7));
    }
}
