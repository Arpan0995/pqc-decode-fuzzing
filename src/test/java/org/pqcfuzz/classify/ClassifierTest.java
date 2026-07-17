package org.pqcfuzz.classify;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests the classification rules, which are the study's instrument: if these are wrong, every reported
 * number is wrong in a way no amount of fuzzing would reveal.
 */
class ClassifierTest {

    private static final int NOMINAL = 32;

    /** A target that reports whatever the test tells it to, so the rules can be tested in isolation. */
    private record StubTarget(TargetKind kind, List<byte[]> genuineInputs) implements FuzzTarget {
        @Override
        public String name() {
            return "stub";
        }

        @Override
        public List<byte[]> seedCorpus() {
            return genuineInputs;
        }

        @Override
        public int nominalInputLength() {
            return NOMINAL;
        }

        @Override
        public boolean accepts(byte[] input) {
            throw new UnsupportedOperationException("the classifier never calls the target");
        }
    }

    private static Classifier verifyTarget(byte[] genuine) {
        return new Classifier(new StubTarget(TargetKind.VERIFY, List.of(genuine)));
    }

    private static Classifier decodeTarget() {
        return new Classifier(new StubTarget(TargetKind.DECODE, List.of(new byte[NOMINAL])));
    }

    @Test
    @DisplayName("verify returning false is the correct rejection, not a defect")
    void verifyReturningFalseIsRejected() {
        assertEquals(Outcome.REJECTED, verifyTarget(new byte[NOMINAL]).classifyReturn(new byte[7], false));
    }

    @Test
    @DisplayName("verify accepting a genuine signature is OK")
    void verifyAcceptingGenuineIsOk() {
        byte[] genuine = "genuine-signature".getBytes();
        assertEquals(Outcome.OK, verifyTarget(genuine).classifyReturn(genuine, true));
    }

    @Test
    @DisplayName("a genuine input is recognised by value, not identity")
    void genuineIsComparedByValue() {
        byte[] genuine = "genuine-signature".getBytes();
        // A mutation can rebuild a genuine input byte-for-byte; that verifying is correct, not a forgery.
        byte[] rebuilt = genuine.clone();
        assertEquals(Outcome.OK, verifyTarget(genuine).classifyReturn(rebuilt, true));
    }

    @Test
    @DisplayName("verify accepting a non-genuine signature is a forgery")
    void verifyAcceptingNonGenuineIsForgery() {
        byte[] genuine = "genuine-signature".getBytes();
        assertEquals(Outcome.ACCEPTED,
                verifyTarget(genuine).classifyReturn("forged-signature".getBytes(), true));
    }

    @Test
    @DisplayName("a decoder accepting a correct-length encoding is OK however corrupt its contents")
    void decodeAcceptingCorrectLengthIsOk() {
        byte[] corrupt = new byte[NOMINAL];
        java.util.Arrays.fill(corrupt, (byte) 0xFF);
        assertEquals(Outcome.OK, decodeTarget().classifyReturn(corrupt, true));
    }

    @Test
    @DisplayName("a decoder accepting a wrong-length encoding is a defect")
    void decodeAcceptingWrongLengthIsAccepted() {
        // The BouncyCastle 1.84 ML-DSA defect in miniature: the decoder swallows a short encoding and
        // reports success. Scoring this OK is what made the instrument blind to a real bug.
        Classifier classifier = decodeTarget();
        assertEquals(Outcome.ACCEPTED, classifier.classifyReturn(new byte[NOMINAL - 1], true));
        assertEquals(Outcome.ACCEPTED, classifier.classifyReturn(new byte[NOMINAL + 1], true));
        assertEquals(Outcome.ACCEPTED, classifier.classifyReturn(new byte[0], true));
    }

    @Test
    @DisplayName("a documented exception is a clean rejection")
    void documentedThrowIsRejected() {
        Classifier classifier = decodeTarget();
        assertEquals(Outcome.REJECTED, classifier.classifyThrow(new IllegalArgumentException("bad length")));
        assertEquals(Outcome.REJECTED,
                classifier.classifyThrow(new org.bouncycastle.crypto.DataLengthException("short")));
        assertEquals(Outcome.REJECTED,
                classifier.classifyThrow(new org.bouncycastle.crypto.CryptoException("nope")));
    }

    @Test
    @DisplayName("a bounds violation is never mistaken for a documented rejection")
    void boundsViolationIsUnexpected() {
        Classifier classifier = decodeTarget();
        assertEquals(Outcome.UNEXPECTED_EXCEPTION,
                classifier.classifyThrow(new ArrayIndexOutOfBoundsException("length -76 is negative")));
        assertEquals(Outcome.UNEXPECTED_EXCEPTION, classifier.classifyThrow(new NegativeArraySizeException()));
        assertEquals(Outcome.UNEXPECTED_EXCEPTION, classifier.classifyThrow(new NullPointerException()));
        assertEquals(Outcome.UNEXPECTED_EXCEPTION, classifier.classifyThrow(new OutOfMemoryError()));
    }
}
