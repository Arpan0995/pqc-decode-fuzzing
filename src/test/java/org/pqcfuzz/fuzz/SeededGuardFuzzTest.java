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
 * Coverage-guided harnesses for the graded synthetic control of design amendment A6. Each starts from
 * the one genuine key and is expected to fail once the fuzzer satisfies the planted guard; how long
 * that takes, as the guard widens, is the measurement. In regression mode (a plain {@code mvn test})
 * each runs the genuine key only, which never reaches the fault.
 */
class SeededGuardFuzzTest {

    private static final long SEED = 20260717;
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
            fail(targetName + ": " + outcome + " on a " + input.length + "-byte input", thrown);
        }
    }

    @FuzzTest(maxDuration = "2m")
    void seededGuardK8(FuzzedDataProvider data) {
        drive("seeded-guard-k8", data);
    }

    @FuzzTest(maxDuration = "2m")
    void seededGuardK16(FuzzedDataProvider data) {
        drive("seeded-guard-k16", data);
    }

    @FuzzTest(maxDuration = "2m")
    void seededGuardK32(FuzzedDataProvider data) {
        drive("seeded-guard-k32", data);
    }

    @FuzzTest(maxDuration = "2m")
    void seededGuardK64(FuzzedDataProvider data) {
        drive("seeded-guard-k64", data);
    }
}
