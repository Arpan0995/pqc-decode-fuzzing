package org.pqcfuzz.control;

import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pqcfuzz.env.Environment;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.Targets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The study's positive control, written as an executable specification.
 *
 * <p>A fuzzing campaign that reports no defects is only worth reading if the harness could have found
 * one. BouncyCastle 1.84 supplies the proof: its ML-DSA public-key decoder performs no length check and
 * accepts any encoding of 33 bytes or more — a 1 MiB blob is a valid ML-DSA-65 key as far as it is
 * concerned — and the resulting object throws {@code ArrayIndexOutOfBoundsException} out of
 * {@code Packing.unpackPublicKey} the moment it is used to verify anything. 1.85 fixes it. ML-KEM and
 * SLH-DSA validated their lengths correctly in both versions; ML-DSA was the outlier.
 *
 * <p>So the same harness, run twice, must find that defect in 1.84 and not in 1.85. These tests pin
 * both halves of that claim, and each is skipped on the version it does not describe. Together they
 * make the null result on 1.85 mean something: the instrument demonstrably detects this defect class on
 * this exact code path.
 *
 * <p>Run the control with {@code mvn test -Dbouncycastle.version=1.84}.
 */
class MlDsaKeyLengthValidationTest {

    /** The correct ML-DSA-65 public key length, in bytes. */
    private static final int CORRECT_LENGTH = 1952;

    /**
     * 32 bytes of rho plus one. The smallest input 1.84 accepts: below this, the decoder happens to
     * throw from an {@code Arrays.copyOfRange} contract violation rather than from any check of its own.
     */
    private static final int SHORTEST_ACCEPTED_BY_1_84 = 33;

    private static boolean isVersionAtLeast185() {
        try {
            return Double.parseDouble(Environment.bouncyCastleVersion()) >= 1.85;
        } catch (NumberFormatException e) {
            return true; // An unrecognised version is assumed current rather than assumed broken.
        }
    }

    private static MLDSAPublicKeyParameters parse(byte[] encoding) {
        return new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, encoding);
    }

    @Test
    @DisplayName("1.85+: wrong-length ML-DSA key encodings are rejected with a documented exception")
    void currentVersionRejectsWrongLengthKeys() {
        assumeTrue(isVersionAtLeast185(),
                "describes the fixed behaviour; running against " + Environment.bouncyCastleVersion());
        for (int length : new int[]{0, 1, 32, 33, 100, CORRECT_LENGTH - 1, CORRECT_LENGTH + 1, 1 << 20}) {
            assertThrows(IllegalArgumentException.class, () -> parse(new byte[length]),
                    length + "-byte encoding was accepted as an ML-DSA-65 public key");
        }
    }

    @Test
    @DisplayName("1.84: wrong-length key encodings are silently accepted (the known defect)")
    void knownDefectVersionAcceptsWrongLengthKeys() {
        assumeTrue(!isVersionAtLeast185(),
                "describes the 1.84 defect; running against " + Environment.bouncyCastleVersion());
        for (int length : new int[]{SHORTEST_ACCEPTED_BY_1_84, 100, CORRECT_LENGTH - 1, 1 << 20}) {
            MLDSAPublicKeyParameters parsed = parse(new byte[length]);
            assertEquals(length, parsed.getEncoded().length,
                    "expected 1.84 to swallow a " + length + "-byte encoding whole");
        }
    }

    @Test
    @DisplayName("1.84: using such a key throws ArrayIndexOutOfBounds out of Packing.unpackPublicKey")
    void knownDefectVersionThrowsWhenTheBogusKeyIsUsed() {
        assumeTrue(!isVersionAtLeast185(),
                "describes the 1.84 defect; running against " + Environment.bouncyCastleVersion());

        // The signature must be a *genuine* one, and that detail is the finding rather than a
        // convenience. ML-DSA verification checks the signature's own structure before it unpacks the
        // public key, so a junk signature is refused early and the bogus key is never touched — an
        // all-zero signature here returns false and throws nothing at all. Only a well-formed signature
        // carries execution as far as unpackPublicKey, where the missing length check bites. Reaching
        // this defect therefore takes a valid signature and an invalid key: exactly the pairing
        // ml-dsa-65-parse-verify drives, and exactly what fuzzing the two entry points separately
        // cannot construct.
        FuzzTarget genuineSignatureOverBogusKey = Targets.create("ml-dsa-65-parse-verify", 7);

        ArrayIndexOutOfBoundsException thrown = assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> genuineSignatureOverBogusKey.accepts(new byte[SHORTEST_ACCEPTED_BY_1_84]));
        assertTrue(thrown.getMessage().contains("negative"),
                "expected a negative-length arraycopy, got: " + thrown.getMessage());
    }

    @Test
    @DisplayName("1.84: a junk signature short-circuits before the bogus key is ever unpacked")
    void knownDefectIsNotReachedByAJunkSignature() {
        assumeTrue(!isVersionAtLeast185(),
                "describes the 1.84 defect; running against " + Environment.bouncyCastleVersion());

        // The negative control for the test above: same bogus key, but a signature that fails its own
        // structural check first. This is why the defect hid — the obvious way to probe for it misses.
        MLDSAPublicKeyParameters bogus = parse(new byte[SHORTEST_ACCEPTED_BY_1_84]);
        MLDSASigner verifier = new MLDSASigner();
        byte[] message = "control".getBytes();
        verifier.init(false, bogus);
        verifier.update(message, 0, message.length);

        assertFalse(verifier.verifySignature(new byte[3309]),
                "an all-zero signature should be refused on its own terms, before the key is unpacked");
    }

    @Test
    @DisplayName("the composed target reproduces the control defect on 1.84 and stays clean on 1.85")
    void composedTargetTracksTheVersion() throws Exception {
        FuzzTarget target = Targets.create("ml-dsa-65-parse-verify", 1);
        byte[] shortKey = new byte[SHORTEST_ACCEPTED_BY_1_84];

        if (isVersionAtLeast185()) {
            // Fixed: refused at the decoder, before anything can go wrong downstream.
            assertThrows(IllegalArgumentException.class, () -> target.accepts(shortKey));
        } else {
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> target.accepts(shortKey));
        }
    }
}
