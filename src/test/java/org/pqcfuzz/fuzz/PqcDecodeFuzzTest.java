package org.pqcfuzz.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.pqcfuzz.classify.Classifier;
import org.pqcfuzz.classify.Outcome;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.Targets;

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
}
