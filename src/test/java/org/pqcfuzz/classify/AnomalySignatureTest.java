package org.pqcfuzz.classify;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Tests the deduplication key that decides how many distinct defects a campaign reports. */
class AnomalySignatureTest {

    private static Throwable withStack(StackTraceElement... frames) {
        Throwable t = new ArrayIndexOutOfBoundsException("length -76 is negative");
        t.setStackTrace(frames);
        return t;
    }

    private static StackTraceElement frame(String cls, String method) {
        return new StackTraceElement(cls, method, null, -1);
    }

    @Test
    @DisplayName("skips JDK frames to find the library code responsible")
    void skipsJdkFrames() {
        AnomalySignature signature = AnomalySignature.of(Outcome.UNEXPECTED_EXCEPTION, withStack(
                frame("java.lang.System", "arraycopy"),
                frame("org.bouncycastle.crypto.signers.mldsa.Packing", "unpackPublicKey")));
        assertEquals("org.bouncycastle.crypto.signers.mldsa.Packing.unpackPublicKey", signature.topFrame());
    }

    @Test
    @DisplayName("skips BouncyCastle's own array utilities, which report bugs rather than cause them")
    void skipsBouncyCastleUtilFrames() {
        // The real 1.84 ML-DSA trace: System.arraycopy -> bc util Arrays.copyOfRange -> Packing.
        // Keying on copyOfRange would merge every unrelated copyOfRange misuse in the library into one.
        AnomalySignature signature = AnomalySignature.of(Outcome.UNEXPECTED_EXCEPTION, withStack(
                frame("java.lang.System", "arraycopy"),
                frame("org.bouncycastle.util.Arrays", "copyOfRange"),
                frame("org.bouncycastle.crypto.signers.mldsa.Packing", "unpackPublicKey")));
        assertEquals("org.bouncycastle.crypto.signers.mldsa.Packing.unpackPublicKey", signature.topFrame());
    }

    @Test
    @DisplayName("two different defects sharing a utility frame stay distinct")
    void distinctDefectsSharingAUtilityDoNotMerge() {
        AnomalySignature packing = AnomalySignature.of(Outcome.UNEXPECTED_EXCEPTION, withStack(
                frame("org.bouncycastle.util.Arrays", "copyOfRange"),
                frame("org.bouncycastle.crypto.signers.mldsa.Packing", "unpackPublicKey")));
        AnomalySignature elsewhere = AnomalySignature.of(Outcome.UNEXPECTED_EXCEPTION, withStack(
                frame("org.bouncycastle.util.Arrays", "copyOfRange"),
                frame("org.bouncycastle.crypto.kems.MLKEMExtractor", "extractSecret")));
        assertNotEquals(packing, elsewhere);
    }

    @Test
    @DisplayName("omits the line number BouncyCastle release jars do not carry")
    void omitsAbsentLineNumbers() {
        AnomalySignature signature = AnomalySignature.of(Outcome.UNEXPECTED_EXCEPTION,
                withStack(frame("org.bouncycastle.crypto.signers.mldsa.Packing", "unpackPublicKey")));
        assertTrue(signature.topFrame().endsWith("unpackPublicKey"),
                "expected no ':-1' suffix, got: " + signature.topFrame());
    }

    @Test
    @DisplayName("keeps the line number when one is available")
    void keepsRealLineNumbers() {
        Throwable t = new NullPointerException();
        t.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("org.example.Thing", "doIt", "Thing.java", 42)});
        assertEquals("org.example.Thing.doIt:42",
                AnomalySignature.of(Outcome.UNEXPECTED_EXCEPTION, t).topFrame());
    }

    @Test
    @DisplayName("survives a stack trace the JIT stripped")
    void handlesEmptyStackTrace() {
        Throwable t = new ArrayIndexOutOfBoundsException();
        t.setStackTrace(new StackTraceElement[0]);
        AnomalySignature signature = AnomalySignature.of(Outcome.UNEXPECTED_EXCEPTION, t);
        assertEquals("-", signature.topFrame());
    }

    @Test
    @DisplayName("outcomes with no exception get a stable signature")
    void outcomesWithoutExceptions() {
        assertEquals(AnomalySignature.of(Outcome.TIMEOUT), AnomalySignature.of(Outcome.TIMEOUT));
        assertNotEquals(AnomalySignature.of(Outcome.TIMEOUT), AnomalySignature.of(Outcome.ACCEPTED));
    }
}
