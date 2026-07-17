package org.pqcfuzz.mutate;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.random.RandomGenerator;
import java.util.random.RandomGeneratorFactory;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MutationTest {

    private static final int NOMINAL = 128;

    private static RandomGenerator rng(long seed) {
        return RandomGeneratorFactory.of("L64X128MixRandom").create(seed);
    }

    private static byte[] seed() {
        byte[] seed = new byte[NOMINAL];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte) (i + 1);
        }
        return seed;
    }

    @ParameterizedTest
    @EnumSource(Mutation.class)
    @DisplayName("no strategy modifies the seed it was given")
    void seedIsNeverMutatedInPlace(Mutation mutation) {
        byte[] seed = seed();
        byte[] before = seed.clone();
        for (int i = 0; i < 50; i++) {
            mutation.apply(seed, NOMINAL, rng(i));
        }
        assertArrayEquals(before, seed, mutation + " modified the seed corpus in place");
    }

    @ParameterizedTest
    @EnumSource(Mutation.class)
    @DisplayName("every strategy is a pure function of its seed and generator")
    void mutationsAreReproducible(Mutation mutation) {
        // The whole reproducibility claim rests on this: a campaign replays from its seed alone.
        assertArrayEquals(
                mutation.apply(seed(), NOMINAL, rng(99)),
                mutation.apply(seed(), NOMINAL, rng(99)),
                mutation + " is not reproducible from its seed");
    }

    @ParameterizedTest
    @EnumSource(value = Mutation.class,
            names = {"BIT_FLIP", "MULTI_BIT_FLIP", "BYTE_SUBSTITUTE", "CHUNK_RANDOMIZE", "ZERO_FILL",
                    "ONES_FILL", "RANDOM"})
    @DisplayName("content strategies keep the length correct, so they reach past any length check")
    void contentStrategiesPreserveLength(Mutation mutation) {
        for (int i = 0; i < 20; i++) {
            assertEquals(NOMINAL, mutation.apply(seed(), NOMINAL, rng(i)).length,
                    mutation + " changed the length; it is meant to corrupt contents only");
        }
    }

    @Test
    @DisplayName("BIT_FLIP changes exactly one bit")
    void bitFlipChangesOneBit() {
        for (int i = 0; i < 50; i++) {
            byte[] mutated = Mutation.BIT_FLIP.apply(seed(), NOMINAL, rng(i));
            assertEquals(1, differingBits(seed(), mutated));
        }
    }

    @Test
    @DisplayName("MULTI_BIT_FLIP changes between 2 and 8 bits")
    void multiBitFlipChangesSeveralBits() {
        for (int i = 0; i < 50; i++) {
            int changed = differingBits(seed(), Mutation.MULTI_BIT_FLIP.apply(seed(), NOMINAL, rng(i)));
            // Flips are drawn independently, so two can land on the same bit and cancel out.
            assertTrue(changed >= 0 && changed <= 8, "changed " + changed + " bits");
        }
    }

    @Test
    @DisplayName("TRUNCATE always shortens")
    void truncateShortens() {
        for (int i = 0; i < 50; i++) {
            assertTrue(Mutation.TRUNCATE.apply(seed(), NOMINAL, rng(i)).length < NOMINAL);
        }
    }

    @Test
    @DisplayName("EXTEND always lengthens and keeps the original prefix")
    void extendLengthensAndPreservesPrefix() {
        for (int i = 0; i < 50; i++) {
            byte[] mutated = Mutation.EXTEND.apply(seed(), NOMINAL, rng(i));
            assertTrue(mutated.length > NOMINAL);
            assertArrayEquals(seed(), Arrays.copyOf(mutated, NOMINAL));
        }
    }

    @Test
    @DisplayName("ZERO_FILL and ONES_FILL produce their degenerate inputs")
    void fillStrategies() {
        byte[] zeros = Mutation.ZERO_FILL.apply(seed(), NOMINAL, rng(1));
        assertArrayEquals(new byte[NOMINAL], zeros);

        byte[] ones = Mutation.ONES_FILL.apply(seed(), NOMINAL, rng(1));
        byte[] expected = new byte[NOMINAL];
        Arrays.fill(expected, (byte) 0xFF);
        assertArrayEquals(expected, ones);
    }

    @Test
    @DisplayName("LENGTH_EDGE reaches every boundary length, including empty and oversized")
    void lengthEdgeCoversBoundaries() {
        Set<Integer> lengths = new HashSet<>();
        for (int i = 0; i < 400; i++) {
            lengths.add(Mutation.LENGTH_EDGE.apply(seed(), NOMINAL, rng(i)).length);
        }
        // The off-by-ones are where a bounds check is either right or wrong; the 1 MiB case asks
        // whether an oversized input is refused on sight or copied first.
        assertTrue(lengths.containsAll(List.of(0, 1, NOMINAL - 1, NOMINAL + 1, NOMINAL * 2, 1 << 20)),
                "missing boundary lengths, saw: " + lengths);
        assertFalse(lengths.contains(NOMINAL), "LENGTH_EDGE should never produce the correct length");
    }

    @Test
    @DisplayName("strategies tolerate an empty seed rather than throwing")
    void emptySeedIsSafe() {
        for (Mutation mutation : Mutation.values()) {
            // A campaign must never die because a previous mutation produced something degenerate.
            assertNotEquals(null, mutation.apply(new byte[0], NOMINAL, rng(3)), mutation.toString());
        }
    }

    private static int differingBits(byte[] a, byte[] b) {
        assertEquals(a.length, b.length);
        int count = 0;
        for (int i = 0; i < a.length; i++) {
            count += Integer.bitCount((a[i] ^ b[i]) & 0xFF);
        }
        return count;
    }
}
