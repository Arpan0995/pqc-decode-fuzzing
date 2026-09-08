package org.pqcfuzz.target.jdk;

import org.pqcfuzz.target.mldsa.MlDsaKeys;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * ML-DSA-65 key material for the JDK targets: the <em>same</em> deterministic key pair the
 * BouncyCastle arm derives from the campaign seed, with its raw public key imported into the JDK.
 *
 * <p>Sharing the key pair, and signing with BouncyCastle's deterministic signer, makes the seed
 * corpora of the two arms byte-identical: the same genuine signature, the same wrong-key signatures,
 * the same key encodings. With identical nominal lengths, the mutation stream is identical too, so
 * the i-th input of a JDK campaign is the i-th input of the BouncyCastle campaign with the same seed.
 * (The JDK signs hedged and ignores a caller-supplied random for the hedge in some versions, so
 * signing there would not reproduce from the seed alone.)
 */
final class JdkMlDsaKeys {

    final MlDsaKeys keys;
    final byte[] rawPublicKey;
    final PublicKey publicKey;

    JdkMlDsaKeys(long seed, KeyFactory factory) {
        this.keys = new MlDsaKeys(seed);
        this.rawPublicKey = keys.publicKey.getEncoded();
        try {
            this.publicKey = JdkPqc.parse(factory, JdkPqc.OID_ML_DSA_65, rawPublicKey);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("the JDK refused a genuine BouncyCastle ML-DSA-65 public key", e);
        }
    }

    byte[] sign(byte[] message) {
        return keys.sign(message);
    }
}
