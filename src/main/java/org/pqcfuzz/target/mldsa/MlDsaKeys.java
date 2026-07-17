package org.pqcfuzz.target.mldsa;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.pqcfuzz.util.DeterministicSecureRandom;

import java.security.SecureRandom;

/**
 * A fixed ML-DSA-65 key pair derived deterministically from a seed, plus signing helpers. Shared by the
 * ML-DSA targets.
 *
 * <p>Uses {@code org.bouncycastle.crypto.{params,signers,generators}} — the current API, and the one
 * {@code PublicKeyFactory} hands back when an X.509 certificate is parsed — rather than the deprecated
 * {@code org.bouncycastle.pqc.crypto.mldsa} package.
 */
final class MlDsaKeys {

    static final MLDSAParameters PARAMETERS = MLDSAParameters.ml_dsa_65;

    final MLDSAPublicKeyParameters publicKey;
    final MLDSAPrivateKeyParameters privateKey;

    MlDsaKeys(long seed) {
        SecureRandom keyRandom = new DeterministicSecureRandom(seed);
        MLDSAKeyPairGenerator kpg = new MLDSAKeyPairGenerator();
        kpg.init(new MLDSAKeyGenerationParameters(keyRandom, PARAMETERS));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        this.publicKey = (MLDSAPublicKeyParameters) kp.getPublic();
        this.privateKey = (MLDSAPrivateKeyParameters) kp.getPrivate();
    }

    /**
     * Sign deterministically (init with the plain private key selects FIPS 204 rnd = 0), so the seed
     * signatures a campaign mutates are a function of the seed alone.
     */
    byte[] sign(byte[] message) {
        MLDSASigner signer = new MLDSASigner();
        signer.init(true, privateKey);
        signer.update(message, 0, message.length);
        try {
            return signer.generateSignature();
        } catch (CryptoException e) {
            throw new IllegalStateException("ML-DSA signing failed while building the seed corpus", e);
        }
    }
}
