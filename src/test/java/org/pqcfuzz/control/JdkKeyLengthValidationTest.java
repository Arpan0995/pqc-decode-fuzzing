package org.pqcfuzz.control;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pqcfuzz.classify.Classifier;
import org.pqcfuzz.classify.Outcome;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.Targets;
import org.pqcfuzz.target.jdk.JdkPqc;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Documents what the JDK arm's construction-time smoke test found (design amendment A5): the JDK's
 * ML-DSA and ML-KEM {@code KeyFactory} accept a SubjectPublicKeyInfo whose inner key has the wrong
 * length, and defer the size check to the point of use, where it fails with a documented
 * {@code InvalidKeyException}. The same {@code KeyFactory} rejects a wrong-length Ed25519 key at
 * parse time.
 *
 * <p>Under the pre-registered classifier this is the {@code ACCEPTED} outcome of amendment A3: a
 * decoder that accepts a wrong-length encoding. It is the same class as the BouncyCastle 1.84
 * positive control, with a different consequence: BouncyCastle 1.84 threw an
 * {@code ArrayIndexOutOfBoundsException} on use, the JDK rejects cleanly on use. These tests pin
 * that behaviour so a future JDK that validates at parse time shows up as a test change, not a
 * silent drift in the campaign numbers.
 */
class JdkKeyLengthValidationTest {

    private static final long SEED = 20260717;

    @BeforeAll
    static void needsJdk24() {
        Assumptions.assumeTrue(JdkPqc.available(), "needs a JDK with ML-DSA and ML-KEM providers (JDK 24 or later)");
    }

    @Test
    @DisplayName("JDK ML-DSA-65 KeyFactory accepts a 33-byte inner key; the parse-only target scores it ACCEPTED")
    void mlDsaParseAcceptsWrongLength() throws Exception {
        FuzzTarget target = Targets.create("jdk-ml-dsa-65-pubkey-parse", SEED);
        byte[] wrongLength = Arrays.copyOf(target.seedCorpus().get(0), 33);
        assertEquals(Outcome.ACCEPTED, new Classifier(target).classifyReturn(wrongLength, target.accepts(wrongLength)));
    }

    @Test
    @DisplayName("JDK ML-KEM-768 KeyFactory accepts a 33-byte inner key; the parse-only target scores it ACCEPTED")
    void mlKemParseAcceptsWrongLength() throws Exception {
        FuzzTarget target = Targets.create("jdk-ml-kem-768-pubkey-parse", SEED);
        byte[] wrongLength = Arrays.copyOf(target.seedCorpus().get(0), 33);
        assertEquals(Outcome.ACCEPTED, new Classifier(target).classifyReturn(wrongLength, target.accepts(wrongLength)));
    }

    @Test
    @DisplayName("using the wrong-length ML-DSA-65 key fails at initVerify with a documented InvalidKeyException")
    void mlDsaUseRejectsWrongLength() {
        FuzzTarget target = Targets.create("jdk-ml-dsa-65-parse-verify", SEED);
        byte[] wrongLength = Arrays.copyOf(target.seedCorpus().get(0), 33);
        Throwable thrown = assertThrows(InvalidKeyException.class, () -> target.accepts(wrongLength));
        assertEquals(Outcome.REJECTED, new Classifier(target).classifyThrow(thrown));
    }

    @Test
    @DisplayName("using the wrong-length ML-KEM-768 key fails at newEncapsulator with a documented InvalidKeyException")
    void mlKemUseRejectsWrongLength() {
        FuzzTarget target = Targets.create("jdk-ml-kem-768-parse-encapsulate", SEED);
        byte[] wrongLength = Arrays.copyOf(target.seedCorpus().get(0), 33);
        Throwable thrown = assertThrows(InvalidKeyException.class, () -> target.accepts(wrongLength));
        assertEquals(Outcome.REJECTED, new Classifier(target).classifyThrow(thrown));
    }

    @Test
    @DisplayName("contrast: the JDK's Ed25519 KeyFactory rejects a wrong-length inner key at parse time")
    void ed25519RejectsWrongLengthAtParse() throws Exception {
        byte[] oidEd25519 = {0x2b, 0x65, 0x70};
        byte[] spki = wrap(oidEd25519, new byte[31]);
        assertThrows(InvalidKeySpecException.class,
                () -> KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki)));
    }

    /** Minimal SubjectPublicKeyInfo builder for short payloads (two-byte or shorter DER lengths). */
    private static byte[] wrap(byte[] oid, byte[] raw) {
        byte[] alg = concat(new byte[] {0x30, (byte) (oid.length + 2), 0x06, (byte) oid.length}, oid);
        byte[] bits = concat(new byte[] {0x03, (byte) (raw.length + 1), 0x00}, raw);
        byte[] body = concat(alg, bits);
        return concat(new byte[] {0x30, (byte) body.length}, body);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
