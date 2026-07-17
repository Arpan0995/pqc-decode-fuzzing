package org.pqcfuzz.target.mlkem;

import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;
import org.pqcfuzz.util.DeterministicSecureRandom;

import java.util.ArrayList;
import java.util.List;

/**
 * ML-KEM-768 <em>parse then encapsulate</em>: decode an attacker-supplied public key and encapsulate to
 * it. The fuzzed input is the <b>key encoding</b>.
 *
 * <p>The KEM's version of the composed path, and the direction of attack is worth being precise about.
 * For signatures the victim is a client parsing a server's certificate; here it is the reverse. In a
 * TLS 1.3 hybrid key exchange the <em>client</em> puts its ML-KEM public key in its key_share, and the
 * <em>server</em> parses that key and encapsulates to it — before any authentication has happened.
 * A server therefore runs this exact sequence on bytes from any unauthenticated peer that can open a
 * connection to it, which makes it the most exposed composed path in the study.
 */
public final class MlKem768ParseAndEncapsulateTarget implements FuzzTarget {

    private static final int SEED_KEYS = 4;

    private final List<byte[]> seeds;
    private final int encodedLength;
    private final MLKEMGenerator generator;

    public MlKem768ParseAndEncapsulateTarget(long seed) {
        List<byte[]> corpus = new ArrayList<>(SEED_KEYS);
        for (int i = 0; i < SEED_KEYS; i++) {
            corpus.add(new MlKemKeys(seed + i).publicKey.getEncoded());
        }
        this.seeds = List.copyOf(corpus);
        this.encodedLength = corpus.get(0).length;
        // Encapsulation consumes randomness; seed it so the campaign stays replayable.
        this.generator = new MLKEMGenerator(new DeterministicSecureRandom(seed ^ 0x0F0F_F0F0L));
    }

    @Override
    public String name() {
        return "ml-kem-768-parse-encapsulate";
    }

    /**
     * Held to the decode contract, not verify: encapsulating to a key asserts nothing about who owns
     * it. Any correct-length key is legitimately encapsulable, so only a wrong-length key being
     * accepted, or a throw, is a defect here.
     */
    @Override
    public TargetKind kind() {
        return TargetKind.DECODE;
    }

    @Override
    public List<byte[]> seedCorpus() {
        return seeds;
    }

    @Override
    public int nominalInputLength() {
        return encodedLength;
    }

    @Override
    public boolean accepts(byte[] input) {
        MLKEMPublicKeyParameters publicKey =
                new MLKEMPublicKeyParameters(MlKemKeys.PARAMETERS, input);
        return generator.generateEncapsulated(publicKey).getEncapsulation() != null;
    }
}
