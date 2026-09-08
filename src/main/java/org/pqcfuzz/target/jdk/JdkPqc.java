package org.pqcfuzz.target.jdk;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KEM;

/**
 * Shared plumbing for the targets that drive the JDK's own ML-KEM (JEP 496, {@code SunJCE}) and
 * ML-DSA (JEP 497, {@code SUN}) providers, shipped since JDK 24.
 *
 * <p>The JDK's public API takes public keys only as X.509 {@code SubjectPublicKeyInfo}, so the
 * targets fuzz the <em>raw</em> key, exactly as the BouncyCastle targets do, and wrap it in a
 * SubjectPublicKeyInfo whose DER lengths are recomputed for the payload. The JDK's DER layer then
 * passes whatever length the mutator produced, and the decision about that length is left to the
 * provider, which is the code under test. This keeps the nominal input lengths, and hence the
 * mutation streams, identical between the two arms.
 */
public final class JdkPqc {

    /** id-ML-DSA-65, 2.16.840.1.101.3.4.3.18. */
    static final byte[] OID_ML_DSA_65 = {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};

    /** id-alg-ml-kem-768, 2.16.840.1.101.3.4.4.2. */
    static final byte[] OID_ML_KEM_768 = {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02};

    private JdkPqc() {
    }

    /** Whether this JVM ships ML-DSA and ML-KEM providers, which JDK 24 and later do. */
    public static boolean available() {
        try {
            KeyFactory.getInstance("ML-DSA-65");
            KeyFactory.getInstance("ML-KEM-768");
            KEM.getInstance("ML-KEM-768");
            return true;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    static KeyFactory keyFactory(String algorithm) {
        try {
            return KeyFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "this JVM has no " + algorithm + " provider; the jdk-* targets need JDK 24 or later", e);
        }
    }

    static KEM kem(String algorithm) {
        try {
            return KEM.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "this JVM has no " + algorithm + " provider; the jdk-* targets need JDK 24 or later", e);
        }
    }

    /** Parse raw key bytes of any length through the JDK's {@code KeyFactory}, wrapped as described above. */
    static PublicKey parse(KeyFactory factory, byte[] oid, byte[] raw) throws InvalidKeySpecException {
        return factory.generatePublic(new X509EncodedKeySpec(spki(oid, raw)));
    }

    /**
     * Wrap raw key bytes in a SubjectPublicKeyInfo: {@code SEQUENCE { SEQUENCE { OID }, BIT STRING }}
     * with no algorithm parameters and zero unused bits, the encoding both providers emit for these
     * algorithms. Lengths are recomputed for the payload, so any payload length is well-formed DER.
     */
    static byte[] spki(byte[] oid, byte[] raw) {
        byte[] bitString = new byte[raw.length + 1];
        System.arraycopy(raw, 0, bitString, 1, raw.length);
        return der(0x30, concat(der(0x30, der(0x06, oid)), der(0x03, bitString)));
    }

    /** The length of the SubjectPublicKeyInfo header that precedes a raw key of the given length. */
    static int headerLength(byte[] oid, int rawLength) {
        return spki(oid, new byte[rawLength]).length - rawLength;
    }

    static byte[] der(int tag, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(body.length + 6);
        out.write(tag);
        int n = body.length;
        if (n < 0x80) {
            out.write(n);
        } else {
            int lengthBytes = n < 0x100 ? 1 : n < 0x1_0000 ? 2 : n < 0x100_0000 ? 3 : 4;
            out.write(0x80 | lengthBytes);
            for (int i = lengthBytes - 1; i >= 0; i--) {
                out.write((n >>> (8 * i)) & 0xFF);
            }
        }
        out.write(body, 0, body.length);
        return out.toByteArray();
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }
}
