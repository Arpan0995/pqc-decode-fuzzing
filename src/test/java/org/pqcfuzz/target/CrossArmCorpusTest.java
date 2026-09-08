package org.pqcfuzz.target;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.pqcfuzz.mutate.Mutator;
import org.pqcfuzz.target.jdk.JdkPqc;

import java.util.List;
import java.util.random.RandomGeneratorFactory;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * Pins the claim design amendment A5 makes about the two arms: for the five key and signature
 * targets, the JDK target's seed corpus, genuine inputs and nominal length are byte-for-byte those of
 * its BouncyCastle counterpart, so the seeded mutator produces the identical stream of inputs for
 * both. The i-th input of a JDK campaign is the i-th input of the BouncyCastle campaign with the same
 * seed. ({@code jdk-ml-kem-768-decap} is the documented exception: JDK 24 cannot import the
 * BouncyCastle private key, so its key pair is the JDK's own.)
 */
class CrossArmCorpusTest {

    private static final long SEED = 20260717;
    private static final int STREAM_LENGTH = 5_000;

    @BeforeAll
    static void needsJdk24() {
        Assumptions.assumeTrue(JdkPqc.available(), "needs a JDK with ML-DSA and ML-KEM providers (JDK 24 or later)");
    }

    static Stream<Arguments> pairs() {
        return Stream.of(
                arguments("ml-kem-768-pubkey-parse", "jdk-ml-kem-768-pubkey-parse"),
                arguments("ml-kem-768-parse-encapsulate", "jdk-ml-kem-768-parse-encapsulate"),
                arguments("ml-dsa-65-verify", "jdk-ml-dsa-65-verify"),
                arguments("ml-dsa-65-pubkey-parse", "jdk-ml-dsa-65-pubkey-parse"),
                arguments("ml-dsa-65-parse-verify", "jdk-ml-dsa-65-parse-verify"));
    }

    @ParameterizedTest
    @MethodSource("pairs")
    @DisplayName("the JDK target's seed corpus is byte-identical to its BouncyCastle counterpart's")
    void seedCorporaAreIdentical(String bc, String jdk) {
        FuzzTarget a = Targets.create(bc, SEED);
        FuzzTarget b = Targets.create(jdk, SEED);
        assertEquals(a.kind(), b.kind(), "kind");
        assertEquals(a.nominalInputLength(), b.nominalInputLength(), "nominal length");
        assertSameBytes(a.seedCorpus(), b.seedCorpus(), "seed corpus");
        assertSameBytes(a.genuineInputs(), b.genuineInputs(), "genuine inputs");
    }

    @ParameterizedTest
    @MethodSource("pairs")
    @DisplayName("the seeded mutation stream is identical for both arms")
    void mutationStreamsAreIdentical(String bc, String jdk) {
        FuzzTarget a = Targets.create(bc, SEED);
        FuzzTarget b = Targets.create(jdk, SEED);
        Mutator ma = new Mutator(a.seedCorpus(), a.nominalInputLength(),
                RandomGeneratorFactory.of("L64X128MixRandom").create(SEED));
        Mutator mb = new Mutator(b.seedCorpus(), b.nominalInputLength(),
                RandomGeneratorFactory.of("L64X128MixRandom").create(SEED));
        for (int i = 0; i < STREAM_LENGTH; i++) {
            assertArrayEquals(ma.next().bytes(), mb.next().bytes(), "input " + i + " differs between arms");
        }
    }

    private static void assertSameBytes(List<byte[]> expected, List<byte[]> actual, String what) {
        assertEquals(expected.size(), actual.size(), what + " size");
        for (int i = 0; i < expected.size(); i++) {
            assertArrayEquals(expected.get(i), actual.get(i), what + " entry " + i);
        }
    }
}
