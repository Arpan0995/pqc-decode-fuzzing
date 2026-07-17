package org.pqcfuzz.run;

import org.pqcfuzz.classify.AnomalySignature;
import org.pqcfuzz.classify.Outcome;
import org.pqcfuzz.mutate.MutatedInput;
import org.pqcfuzz.mutate.Mutation;
import org.pqcfuzz.mutate.Mutator;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.random.RandomGenerator;
import java.util.random.RandomGeneratorFactory;

/** Runs one target's mutation campaign end to end and reports what it found (design §5). */
public final class CampaignRunner {

    private static final long PROGRESS_INTERVAL = 25_000;

    private final long timeoutMillis;
    private final boolean minimize;
    private final PrintStream log;

    public CampaignRunner(long timeoutMillis, boolean minimize, PrintStream log) {
        this.timeoutMillis = timeoutMillis;
        this.minimize = minimize;
        this.log = log;
    }

    /**
     * Validate the seeds, then drive {@code inputs} mutated inputs through the target.
     *
     * @param seed seeds the mutation stream; combined with the target's own seed, it makes the campaign
     *     replayable
     */
    public TargetResult run(FuzzTarget target, long seed, long inputs) {
        try (TargetExecutor executor = new TargetExecutor(target, timeoutMillis)) {
            validateSeeds(target, executor);

            Mutator mutator = new Mutator(
                    target.seedCorpus(),
                    target.nominalInputLength(),
                    RandomGeneratorFactory.of("L64X128MixRandom").create(seed));

            Map<Outcome, Long> outcomes = new EnumMap<>(Outcome.class);
            Map<Mutation, Map<Outcome, Long>> byMutation = new EnumMap<>(Mutation.class);
            Map<Outcome, Long> atNominalLength = new EnumMap<>(Outcome.class);
            Map<AnomalySignature, Anomaly> anomalies = new LinkedHashMap<>();

            long start = System.nanoTime();
            long executed = 0;
            for (long i = 0; i < inputs; i++) {
                MutatedInput input = mutator.next();
                Execution execution = executor.execute(input.bytes());
                executed++;

                Outcome outcome = execution.outcome();
                outcomes.merge(outcome, 1L, Long::sum);
                byMutation
                        .computeIfAbsent(input.mutation(), m -> new EnumMap<>(Outcome.class))
                        .merge(outcome, 1L, Long::sum);
                if (input.bytes().length == target.nominalInputLength()) {
                    atNominalLength.merge(outcome, 1L, Long::sum);
                }

                if (outcome.isAnomaly()) {
                    record(anomalies, execution, input);
                }
                if ((i + 1) % PROGRESS_INTERVAL == 0) {
                    log.printf("    %s: %,d/%,d inputs, %d distinct anomal%s%n",
                            target.name(), i + 1, inputs, anomalies.size(),
                            anomalies.size() == 1 ? "y" : "ies");
                }
            }
            long elapsed = System.nanoTime() - start;

            List<Anomaly> found = rankAndMinimize(anomalies, executor, target);
            return new TargetResult(
                    target.name(),
                    target.kind(),
                    target.nominalInputLength(),
                    executed,
                    elapsed,
                    outcomes,
                    byMutation,
                    atNominalLength,
                    found,
                    executor.abandonedThreads());
        }
    }

    /**
     * Check the target's own seeds before trusting anything it reports: every genuine input must be
     * accepted, and every seed that is not genuine must be cleanly rejected.
     *
     * <p>This is the control that makes a null result meaningful. The headline finding of a study like
     * this may well be "no defects found", and a harness that silently failed to drive the library —
     * a key that never loaded, a message that did not match its signature — would report exactly that,
     * with every input dutifully "REJECTED". Confirming that real signatures verify and wrong-key ones
     * do not proves the pipeline is live, so a subsequent absence of anomalies is evidence rather than
     * an artefact.
     */
    private void validateSeeds(FuzzTarget target, TargetExecutor executor) {
        List<byte[]> genuine = target.genuineInputs();
        if (genuine.isEmpty()) {
            throw new SeedValidationException(target.name() + " declares no genuine inputs, so nothing"
                    + " establishes that the harness drives the library at all");
        }
        for (int i = 0; i < genuine.size(); i++) {
            Execution execution = executor.execute(genuine.get(i));
            if (execution.outcome() != Outcome.OK) {
                throw new SeedValidationException(String.format(
                        "%s: genuine input %d was not accepted (got %s%s). The harness is not exercising"
                                + " the library correctly; no result from it would be trustworthy.",
                        target.name(), i, execution.outcome(), detailOf(execution)));
            }
        }
        if (target.kind() != TargetKind.VERIFY) {
            return;
        }
        List<byte[]> seeds = target.seedCorpus();
        for (int i = 0; i < seeds.size(); i++) {
            if (containsIdentical(genuine, seeds.get(i))) {
                continue;
            }
            Execution execution = executor.execute(seeds.get(i));
            if (execution.outcome() != Outcome.REJECTED) {
                throw new SeedValidationException(String.format(
                        "%s: seed %d is a wrong-key signature and must be rejected, but got %s%s.%s",
                        target.name(), i, execution.outcome(), detailOf(execution),
                        execution.outcome() == Outcome.ACCEPTED
                                ? " If this is not a harness bug it is a break of the signature scheme;"
                                        + " verify by hand before believing it."
                                : ""));
            }
        }
    }

    private static String detailOf(Execution execution) {
        return execution.thrown() == null
                ? ""
                : ": " + execution.thrown().getClass().getName() + " " + execution.detail();
    }

    private static boolean containsIdentical(List<byte[]> haystack, byte[] needle) {
        for (byte[] candidate : haystack) {
            if (java.util.Arrays.equals(candidate, needle)) {
                return true;
            }
        }
        return false;
    }

    private static void record(Map<AnomalySignature, Anomaly> anomalies, Execution execution,
                               MutatedInput input) {
        AnomalySignature signature = execution.signature();
        Anomaly existing = anomalies.get(signature);
        if (existing != null) {
            existing.recordHit(input.bytes(), input.mutation(), input.seedIndex());
            return;
        }
        anomalies.put(signature, new Anomaly(
                signature,
                execution.detail(),
                stackTraceOf(execution.thrown()),
                input.bytes(),
                input.mutation(),
                input.seedIndex()));
    }

    private static String stackTraceOf(Throwable t) {
        if (t == null) {
            return "";
        }
        StringWriter out = new StringWriter();
        t.printStackTrace(new PrintWriter(out));
        return out.toString();
    }

    /** Order defects by how often they fired, then shrink each one's reproducer. */
    private List<Anomaly> rankAndMinimize(Map<AnomalySignature, Anomaly> anomalies,
                                          TargetExecutor executor, FuzzTarget target) {
        List<Anomaly> found = new ArrayList<>(anomalies.values());
        found.sort(Comparator.comparingLong(Anomaly::count).reversed());
        if (!minimize || found.isEmpty()) {
            return List.copyOf(found);
        }
        log.printf("    %s: minimizing %d reproducer%s%n",
                target.name(), found.size(), found.size() == 1 ? "" : "s");
        Minimizer minimizer = new Minimizer(executor);
        for (Anomaly anomaly : found) {
            anomaly.replaceReproducer(minimizer.minimize(anomaly.reproducer(), anomaly.signature()));
        }
        return List.copyOf(found);
    }

    /** Thrown when a target's own valid inputs do not behave, which invalidates everything downstream. */
    public static final class SeedValidationException extends RuntimeException {
        SeedValidationException(String message) {
            super(message);
        }
    }
}
