package org.pqcfuzz.target;

import org.pqcfuzz.target.control.SeededGuardTarget;
import org.pqcfuzz.target.control.SeededHangTarget;
import org.pqcfuzz.target.jdk.JdkMlDsa65ParseAndVerifyTarget;
import org.pqcfuzz.target.jdk.JdkMlDsa65PublicKeyParseTarget;
import org.pqcfuzz.target.jdk.JdkMlDsa65VerifyTarget;
import org.pqcfuzz.target.jdk.JdkMlKem768DecapTarget;
import org.pqcfuzz.target.jdk.JdkMlKem768ParseAndEncapsulateTarget;
import org.pqcfuzz.target.jdk.JdkMlKem768PublicKeyParseTarget;
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
        // Amendment A5: the same entry points in the JDK's own providers (JDK 24 and later). The JDK
        // has no SLH-DSA, so there are six, not nine.
        register("jdk-ml-kem-768-decap", JdkMlKem768DecapTarget::new);
        register("jdk-ml-kem-768-pubkey-parse", JdkMlKem768PublicKeyParseTarget::new);
        register("jdk-ml-dsa-65-verify", JdkMlDsa65VerifyTarget::new);
        register("jdk-ml-dsa-65-pubkey-parse", JdkMlDsa65PublicKeyParseTarget::new);
        register("jdk-ml-kem-768-parse-encapsulate", JdkMlKem768ParseAndEncapsulateTarget::new);
        register("jdk-ml-dsa-65-parse-verify", JdkMlDsa65ParseAndVerifyTarget::new);
    }

    private Targets() {
    }

    private static void register(String name, LongFunction<FuzzTarget> factory) {
        FACTORIES.put(name, factory);
    }

    /** All target names, in a stable order: the nine BouncyCastle targets, then the six JDK ones. */
    public static List<String> names() {
        return List.copyOf(FACTORIES.keySet());
    }

    /** The nine BouncyCastle targets: the pre-registered six plus the three composed paths. */
    public static List<String> bcNames() {
        return names().stream().filter(n -> !n.startsWith("jdk-")).toList();
    }

    /** The six targets that drive the JDK's own providers (amendment A5); they need JDK 24 or later. */
    public static List<String> jdkNames() {
        return names().stream().filter(n -> n.startsWith("jdk-")).toList();
    }

    /**
     * Build the named target, seeded for reproducibility. Building is not cheap — it generates key
     * pairs and real signatures — so callers should build once per campaign, not per input.
     *
     * @throws IllegalArgumentException if no such target is registered
     */
    public static FuzzTarget create(String name, long seed) {
        if (name.startsWith(SeededHangTarget.PREFIX)) {
            // The synthetic hang control of amendment A7; unregistered for the same reason as the guard.
            return new SeededHangTarget(Integer.parseInt(name.substring(SeededHangTarget.PREFIX.length())), seed);
        }
        if (name.startsWith(SeededGuardTarget.PREFIX)) {
            // The synthetic control of amendment A6. Deliberately not registered: it must never run as
            // part of "bc", "jdk" or "all", whose results are read as evidence about a library.
            return new SeededGuardTarget(Integer.parseInt(name.substring(SeededGuardTarget.PREFIX.length())), seed);
        }
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
