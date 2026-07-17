package org.pqcfuzz.target.mlkem;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.pqcfuzz.util.DeterministicSecureRandom;

import java.security.SecureRandom;

/**
 * A fixed ML-KEM-768 key pair and decapsulation extractor, derived deterministically from a seed so a
 * campaign is reproducible. Shared by the ML-KEM targets.
 *
 * <p>Uses {@code org.bouncycastle.crypto.{params,kems,generators}} — the current API — rather than the
 * {@code org.bouncycastle.pqc.crypto.mlkem} package, which BouncyCastle deprecated. See
 * {@link org.pqcfuzz.target.FuzzTarget} for why that choice decides what this study is measuring.
 */
final class MlKemKeys {

    static final MLKEMParameters PARAMETERS = MLKEMParameters.ml_kem_768;

    final MLKEMPublicKeyParameters publicKey;
    final MLKEMPrivateKeyParameters privateKey;
    final MLKEMExtractor extractor;

    private final SecureRandom encapRandom;

    MlKemKeys(long seed) {
        SecureRandom keyRandom = new DeterministicSecureRandom(seed);
        MLKEMKeyPairGenerator kpg = new MLKEMKeyPairGenerator();
        kpg.init(new MLKEMKeyGenerationParameters(keyRandom, PARAMETERS));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        this.publicKey = (MLKEMPublicKeyParameters) kp.getPublic();
        this.privateKey = (MLKEMPrivateKeyParameters) kp.getPrivate();
        this.extractor = new MLKEMExtractor(privateKey);
        // Distinct stream for encapsulations, so seed ciphertexts vary but stay reproducible.
        this.encapRandom = new DeterministicSecureRandom(seed ^ 0x5555_AAAAL);
    }

    /** One valid encapsulation (shared secret + ciphertext) against the public key. */
    SecretWithEncapsulation encapsulate() {
        return new MLKEMGenerator(encapRandom).generateEncapsulated(publicKey);
    }
}
