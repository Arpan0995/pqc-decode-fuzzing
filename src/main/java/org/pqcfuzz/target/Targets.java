package org.pqcfuzz.target;

import org.pqcfuzz.target.mldsa.MlDsa65ParseAndVerifyTarget;
import org.pqcfuzz.target.mldsa.MlDsa65PublicKeyParseTarget;
import org.pqcfuzz.target.mldsa.MlDsa65VerifyTarget;
import org.pqcfuzz.target.mlkem.MlKem768DecapTarget;
import org.pqcfuzz.target.mlkem.MlKem768ParseAndEncapsulateTarget;
import org.pqcfuzz.target.mlkem.MlKem768PublicKeyParseTarget;
import org.pqcfuzz.target.slhdsa.SlhDsaParseAndVerifyTarget;
import org.pqcfuzz.target.slhdsa.SlhDsaPublicKeyParseTarget;
import org.pqcfuzz.target.slhdsa.SlhDsaVerifyTarget;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongFunction;

/**
 * The registry of targets under test: the six entry points pre-registered in the design (§2), plus the
 * three composed paths added in amendment A2 (§12).
 *
 * <p>The composed targets are the ones that catch defects living between two functions rather than
 * inside either — which is where the one real defect this study has found so far turned out to live.
 */
public final class Targets {

    private static final Map<String, LongFunction<FuzzTarget>> FACTORIES = new LinkedHashMap<>();

    static {
        // Pre-registered: the individual entry points.
        register("ml-kem-768-decap", MlKem768DecapTarget::new);
        register("ml-kem-768-pubkey-parse", MlKem768PublicKeyParseTarget::new);
        register("ml-dsa-65-verify", MlDsa65VerifyTarget::new);
        register("ml-dsa-65-pubkey-parse", MlDsa65PublicKeyParseTarget::new);
        register("slh-dsa-sha2-128f-verify", SlhDsaVerifyTarget::new);
        register("slh-dsa-sha2-128f-pubkey-parse", SlhDsaPublicKeyParseTarget::new);
        // Amendment A2: the composed paths a real peer drives — parse an untrusted key, then use it.
        register("ml-kem-768-parse-encapsulate", MlKem768ParseAndEncapsulateTarget::new);
        register("ml-dsa-65-parse-verify", MlDsa65ParseAndVerifyTarget::new);
        register("slh-dsa-sha2-128f-parse-verify", SlhDsaParseAndVerifyTarget::new);
    }

    private Targets() {
    }

    private static void register(String name, LongFunction<FuzzTarget> factory) {
        FACTORIES.put(name, factory);
    }

    /** All target names, in a stable order. */
    public static List<String> names() {
        return List.copyOf(FACTORIES.keySet());
    }

    /**
     * Build the named target, seeded for reproducibility. Building is not cheap — it generates key
     * pairs and real signatures — so callers should build once per campaign, not per input.
     *
     * @throws IllegalArgumentException if no such target is registered
     */
    public static FuzzTarget create(String name, long seed) {
        LongFunction<FuzzTarget> factory = FACTORIES.get(name);
        if (factory == null) {
            throw new IllegalArgumentException(
                    "Unknown target '" + name + "'; known targets: " + String.join(", ", names()));
        }
        FuzzTarget target = factory.apply(seed);
        if (!target.name().equals(name)) {
            throw new IllegalStateException(
                    "Target registered as '" + name + "' reports name '" + target.name() + "'");
        }
        return target;
    }

    /** Build every registered target with the same seed. */
    public static List<FuzzTarget> createAll(long seed) {
        return names().stream().map(n -> create(n, seed)).toList();
    }
}
