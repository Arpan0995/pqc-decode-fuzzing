package org.pqcfuzz.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.pqcfuzz.classify.Classifier;
import org.pqcfuzz.classify.Outcome;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.Targets;
import org.pqcfuzz.target.jdk.JdkPqc;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Coverage-guided fuzzing of the same targets, driven by Jazzer (design §5.1).
 *
 * <p>The complement to the mutation campaign, and the answer to its main weakness. {@code FuzzCampaign}
 * generates inputs blind: it damages a valid encoding and hopes the damage lands somewhere interesting,
 * with nothing steering it. Jazzer instruments the library and evolves inputs toward <em>new coverage</em>,
 * so it can find its own way down a branch that random mutation would reach only by luck. The campaign
 * is the workhorse that produces the reported numbers; this is the part that can surprise it.
 *
 * <p>Each harness asserts the same contract the campaign classifies against, via the same
 * {@link Classifier}. That sharing is deliberate — two fuzzers disagreeing about what counts as a defect
 * would make their results incomparable.
 *
 * <p><b>Running.</b> By default these execute in JUnit regression mode: each replays its saved corpus
 * and returns, which is fast enough for CI. To actually fuzz, set {@code JAZZER_FUZZ=1}:
 *
 * <pre>{@code
 * JAZZER_FUZZ=1 mvn test -Dtest=PqcDecodeFuzzTest
 * JAZZER_FUZZ=1 mvn test -Dtest=PqcDecodeFuzzTest -Dbouncycastle.version=1.84   # the control
 * }</pre>
 *
 * <p>Against 1.84 the ML-DSA harnesses are <em>expected to fail</em>: that version's decoder has a real
 * defect, and a fuzzer that did not find it would be the thing worth worrying about.
 */
class PqcDecodeFuzzTest {

    private static final long SEED = 20260717;

    /** Targets are expensive to build — key generation and real signatures — so build each once. */
    private static final Map<String, FuzzTarget> TARGETS = new ConcurrentHashMap<>();
    private static final Map<String, Classifier> CLASSIFIERS = new ConcurrentHashMap<>();

    private static void drive(String targetName, FuzzedDataProvider data) {
        FuzzTarget target = TARGETS.computeIfAbsent(targetName, n -> Targets.create(n, SEED));
        Classifier classifier = CLASSIFIERS.computeIfAbsent(targetName, n -> new Classifier(target));
        byte[] input = data.consumeRemainingAsBytes();

        Outcome outcome;
        Throwable thrown = null;
        try {
            outcome = classifier.classifyReturn(input, target.accepts(input));
        } catch (Throwable t) {
            thrown = t;
            outcome = classifier.classifyThrow(t);
        }
        if (outcome.isAnomaly()) {
            fail(describe(targetName, outcome, input, thrown), thrown);
        }
    }

    private static boolean fuzzing() {
        String flag = System.getenv("JAZZER_FUZZ");
        return flag != null && !flag.isEmpty() && !flag.equals("0");
    }

    /** True on BouncyCastle 1.84, the positive control whose ML-DSA key decoder accepts any length. */
    private static boolean isControlVersion() {
        try {
            return Double.parseDouble(org.pqcfuzz.env.Environment.bouncyCastleVersion()) < 1.85;
        } catch (NumberFormatException e) {
            return false; // An unrecognised version is assumed current rather than assumed broken.
        }
    }

    private static String describe(String target, Outcome outcome, byte[] input, Throwable thrown) {
        String detail = thrown == null ? "no exception" : thrown.getClass().getName() + ": " + thrown.getMessage();
        return String.format("%s: %s on a %d-byte input (%s)", target, outcome, input.length, detail);
    }

    // Jazzer has no notion of a per-input timeout of our own, so hangs surface as its own -timeout
    // libFuzzer flag rather than as Outcome.TIMEOUT. Everything else classifies identically.

    @FuzzTest(maxDuration = "2m")
    void mlKemDecap(FuzzedDataProvider data) {
        drive("ml-kem-768-decap", data);
    }

    @FuzzTest(maxDuration = "2m")
    void mlKemPublicKeyParse(FuzzedDataProvider data) {
        drive("ml-kem-768-pubkey-parse", data);
    }

    @FuzzTest(maxDuration = "2m")
    void mlKemParseAndEncapsulate(FuzzedDataProvider data) {
        drive("ml-kem-768-parse-encapsulate", data);
    }

    @FuzzTest(maxDuration = "2m")
    void mlDsaVerify(FuzzedDataProvider data) {
        drive("ml-dsa-65-verify", data);
    }

    @FuzzTest(maxDuration = "2m")
    void mlDsaPublicKeyParse(FuzzedDataProvider data) {
        // The over-length seed is itself accepted by the 1.84 control, which is the defect. Replaying the
        // seeds in a plain "mvn test" would then turn the control's documented green suite red, so on
        // 1.84 this harness runs only when it is actually fuzzing (JAZZER_FUZZ=1), where failing is the point.
        Assumptions.assumeTrue(fuzzing() || !isControlVersion(),
                "BouncyCastle 1.84 control: run this harness with JAZZER_FUZZ=1");
        drive("ml-dsa-65-pubkey-parse", data);
    }

    /** Expected to fail on BouncyCastle 1.84: this is the path carrying the known control defect. */
    @FuzzTest(maxDuration = "2m")
    void mlDsaParseAndVerify(FuzzedDataProvider data) {
        drive("ml-dsa-65-parse-verify", data);
    }

    @FuzzTest(maxDuration = "2m")
    void slhDsaVerify(FuzzedDataProvider data) {
        drive("slh-dsa-sha2-128f-verify", data);
    }

    @FuzzTest(maxDuration = "2m")
    void slhDsaPublicKeyParse(FuzzedDataProvider data) {
        drive("slh-dsa-sha2-128f-pubkey-parse", data);
    }

    @FuzzTest(maxDuration = "2m")
    void slhDsaParseAndVerify(FuzzedDataProvider data) {
        drive("slh-dsa-sha2-128f-parse-verify", data);
    }

    // Amendment A5: the same entry points in the JDK's own providers. Skipped below JDK 24.

    private static void driveJdk(String targetName, FuzzedDataProvider data) {
        Assumptions.assumeTrue(JdkPqc.available(), "needs JDK 24 or later");
        drive(targetName, data);
    }

    @FuzzTest(maxDuration = "2m")
    void jdkMlKemDecap(FuzzedDataProvider data) {
        driveJdk("jdk-ml-kem-768-decap", data);
    }

    /**
     * Fails by design on JDK 24 and later, within seconds and on the empty input: the JDK's
     * {@code KeyFactory} accepts a wrong-length key (design amendment A5), which the classifier
     * scores {@code ACCEPTED}. That is the harness working, as with the 1.84 control. The behaviour
     * is pinned by {@code JdkKeyLengthValidationTest}; this harness is opt-in
     * ({@code -Dpqcfuzz.jdk.parse=true}) so {@code mvn test} stays green on a clean library.
     */
    @EnabledIfSystemProperty(named = "pqcfuzz.jdk.parse", matches = "true")
    @FuzzTest(maxDuration = "2m")
    void jdkMlKemPublicKeyParse(FuzzedDataProvider data) {
        driveJdk("jdk-ml-kem-768-pubkey-parse", data);
    }

    @FuzzTest(maxDuration = "2m")
    void jdkMlKemParseAndEncapsulate(FuzzedDataProvider data) {
        driveJdk("jdk-ml-kem-768-parse-encapsulate", data);
    }

    @FuzzTest(maxDuration = "2m")
    void jdkMlDsaVerify(FuzzedDataProvider data) {
        driveJdk("jdk-ml-dsa-65-verify", data);
    }

    /** Same as {@link #jdkMlKemPublicKeyParse}: fails by design on JDK 24 and later; opt-in. */
    @EnabledIfSystemProperty(named = "pqcfuzz.jdk.parse", matches = "true")
    @FuzzTest(maxDuration = "2m")
    void jdkMlDsaPublicKeyParse(FuzzedDataProvider data) {
        driveJdk("jdk-ml-dsa-65-pubkey-parse", data);
    }

    @FuzzTest(maxDuration = "2m")
    void jdkMlDsaParseAndVerify(FuzzedDataProvider data) {
        driveJdk("jdk-ml-dsa-65-parse-verify", data);
    }
}
