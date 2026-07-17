package org.pqcfuzz.target.slhdsa;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.pqcfuzz.util.DeterministicSecureRandom;

import java.security.SecureRandom;

/**
 * A fixed SLH-DSA key pair derived deterministically from a seed, plus a signing helper. Shared by the
 * SLH-DSA targets.
 *
 * <p>Uses {@code org.bouncycastle.crypto.{params,signers,generators}} — the current API — rather than
 * the deprecated {@code org.bouncycastle.pqc.crypto.slhdsa} package.
 */
final class SlhDsaKeys {

    /**
     * SLH-DSA-SHA2-128f. The {@code f} ("fast") parameter set trades signature size for signing speed,
     * giving a 17088-byte signature — by far the largest input in this study, and the one with the most
     * internal structure (a hypertree of WOTS+ and FORS components) for a decoder to get wrong.
     */
    static final SLHDSAParameters PARAMETERS = SLHDSAParameters.sha2_128f;

    final SLHDSAPublicKeyParameters publicKey;
    final SLHDSAPrivateKeyParameters privateKey;

    SlhDsaKeys(long seed) {
        SecureRandom keyRandom = new DeterministicSecureRandom(seed);
        SLHDSAKeyPairGenerator kpg = new SLHDSAKeyPairGenerator();
        kpg.init(new SLHDSAKeyGenerationParameters(keyRandom, PARAMETERS));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
        this.publicKey = (SLHDSAPublicKeyParameters) kp.getPublic();
        this.privateKey = (SLHDSAPrivateKeyParameters) kp.getPrivate();
    }

    byte[] sign(byte[] message) {
        SLHDSASigner signer = new SLHDSASigner();
        signer.init(true, privateKey);
        return signer.generateSignature(message);
    }
}
