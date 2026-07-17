package org.pqcfuzz.target;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pqcfuzz.classify.Classifier;
import org.pqcfuzz.classify.Outcome;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Checks that every registered target really drives the library.
 *
 * <p>These are the control tests behind every null result the study reports. A harness that failed to
 * exercise BouncyCastle at all — a key that never loaded, a message that never matched its signature —
 * would report a serene absence of defects, which is indistinguishable from the assurance result this
 * study might publish. Proving that genuine inputs are accepted and wrong-key ones rejected is what
 * makes "we found nothing" evidence rather than an artefact.
 */
class TargetsTest {

    private static final long SEED = 4242;

    static List<String> targetNames() {
        return Targets.names();
    }

    @ParameterizedTest
    @MethodSource("targetNames")
    @DisplayName("genuine inputs are accepted")
    void genuineInputsAreAccepted(String name) throws Exception {
        FuzzTarget target = Targets.create(name, SEED);
        Classifier classifier = new Classifier(target);
        assertFalse(target.genuineInputs().isEmpty(), name + " declares no genuine inputs");
        for (byte[] genuine : target.genuineInputs()) {
            assertEquals(Outcome.OK, classifier.classifyReturn(genuine, target.accepts(genuine)),
                    name + " did not accept its own genuine input");
        }
    }

    @ParameterizedTest
    @MethodSource("targetNames")
    @DisplayName("seeds that are not genuine are cleanly rejected")
    void nonGenuineSeedsAreRejected(String name) throws Exception {
        FuzzTarget target = Targets.create(name, SEED);
        if (target.kind() != TargetKind.VERIFY) {
            return; // Only verify targets carry seeds they are meant to refuse.
        }
        Classifier classifier = new Classifier(target);
        for (byte[] seed : target.seedCorpus()) {
            if (target.genuineInputs().stream().anyMatch(g -> Arrays.equals(g, seed))) {
                continue;
            }
            // A wrong-key signature must verify false. If it verified true the scheme would be broken.
            assertEquals(Outcome.REJECTED, classifier.classifyReturn(seed, target.accepts(seed)),
                    name + " accepted a wrong-key signature");
        }
    }

    @ParameterizedTest
    @MethodSource("targetNames")
    @DisplayName("seeds are well-formed and the nominal length is honest")
    void seedsAreWellFormed(String name) {
        FuzzTarget target = Targets.create(name, SEED);
        assertFalse(target.seedCorpus().isEmpty(), name + " has no seeds to mutate");
        assertTrue(target.nominalInputLength() > 0, name + " reports a non-positive nominal length");
        for (byte[] genuine : target.genuineInputs()) {
            assertEquals(target.nominalInputLength(), genuine.length,
                    name + " reports a nominal length its own genuine input does not have");
        }
    }

    @ParameterizedTest
    @MethodSource("targetNames")
    @DisplayName("targets are reproducible from their seed")
    void targetsAreReproducible(String name) {
        // Every reported anomaly is replayed from the campaign seed, so identical seeds must give
        // identical keys, corpora and signatures.
        List<byte[]> first = Targets.create(name, SEED).seedCorpus();
        List<byte[]> second = Targets.create(name, SEED).seedCorpus();
        assertEquals(first.size(), second.size());
        for (int i = 0; i < first.size(); i++) {
            assertTrue(Arrays.equals(first.get(i), second.get(i)),
                    name + " seed " + i + " differs across runs with the same campaign seed");
        }
    }

    @ParameterizedTest
    @MethodSource("targetNames")
    @DisplayName("different seeds give different keys")
    void differentSeedsGiveDifferentKeys(String name) {
        byte[] a = Targets.create(name, SEED).genuineInputs().get(0);
        byte[] b = Targets.create(name, SEED + 1).genuineInputs().get(0);
        assertFalse(Arrays.equals(a, b), name + " ignores its seed");
    }

    @Test
    @DisplayName("the registry is consistent")
    void registryIsConsistent() {
        Set<String> names = new HashSet<>(Targets.names());
        assertEquals(Targets.names().size(), names.size(), "duplicate target names");
        assertEquals(9, names.size(), "expected the six pre-registered targets plus three composed");
        assertThrows(IllegalArgumentException.class, () -> Targets.create("no-such-target", SEED));
    }

    @Test
    @DisplayName("every target uses the current BouncyCastle API, not the deprecated pqc.crypto shim")
    void targetsUseTheModernApi() throws Exception {
        // The deprecated and current classes share simple names, so a stray import is invisible in
        // review and would silently move the study off the code that X.509 parsing actually reaches.
        for (String name : Targets.names()) {
            FuzzTarget target = Targets.create(name, SEED);
            try {
                target.accepts(new byte[0]);
            } catch (Throwable expected) {
                // Only the frames matter here, not the outcome.
            }
            assertDrivesModernApi(target);
        }
    }

    private static void assertDrivesModernApi(FuzzTarget target) {
        // Provoke a throw from inside the library and inspect where it came from.
        Throwable thrown = null;
        try {
            target.accepts(new byte[target.nominalInputLength() - 1]);
        } catch (Throwable t) {
            thrown = t;
        }
        if (thrown == null) {
            return; // Some targets accept short input (that is the 1.84 defect); nothing to inspect.
        }
        for (StackTraceElement frame : thrown.getStackTrace()) {
            assertFalse(frame.getClassName().startsWith("org.bouncycastle.pqc.crypto."),
                    target.name() + " reaches the deprecated API at " + frame);
        }
    }
}
