package org.pqcfuzz;

import org.pqcfuzz.env.Environment;
import org.pqcfuzz.report.CorpusWriter;
import org.pqcfuzz.report.ReportWriter;
import org.pqcfuzz.run.CampaignRunner;
import org.pqcfuzz.run.TargetResult;
import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.Targets;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The campaign entry point: drive every target with mutated inputs, classify what happens, and write
 * the results and reproducers to disk.
 *
 * <pre>{@code
 * java -XX:-OmitStackTraceInFastThrow -jar target/pqc-fuzz.jar [options]
 *
 *   --targets=a,b     targets to run (default: all)
 *   --inputs=N        inputs per target (default: 100000)
 *   --seed=N          campaign seed; fixes keys, corpus and mutations (default: 20260717)
 *   --timeout-ms=N    per-input budget (default: 5000)
 *   --out=DIR         where results are written (default: results)
 *   --no-minimize     skip reproducer minimization
 * }</pre>
 */
public final class FuzzCampaign {

    private FuzzCampaign() {
    }

    public static void main(String[] args) throws IOException {
        Options options;
        try {
            options = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println(Options.usage());
            System.exit(2);
            return;
        }

        if (!Environment.hasFullStackTraces()) {
            System.err.println("warning: this JVM was started without " + Environment.STACK_TRACE_FLAG
                    + ", so the JIT may strip stack traces from repeated implicit exceptions"
                    + " (ArrayIndexOutOfBounds and friends) once they get hot. Those are exactly the"
                    + " defects being hunted, and anomalies are deduplicated by their top stack frame,"
                    + " so distinct bugs may silently collapse into one frameless signature. Re-run with"
                    + " the flag before trusting any anomaly counts.");
        }

        System.out.printf("pqc-decode-fuzzing: BouncyCastle %s on %s%n",
                Environment.bouncyCastleVersion(), Environment.jvm());
        System.out.printf("%d target(s), %,d inputs each, seed %d, %d ms timeout%n%n",
                options.targets().size(), options.inputs(), options.seed(), options.timeoutMillis());

        CampaignRunner runner = new CampaignRunner(options.timeoutMillis(), options.minimize(), System.out);
        List<TargetResult> results = new ArrayList<>(options.targets().size());
        for (String name : options.targets()) {
            System.out.println("  " + name);
            FuzzTarget target = Targets.create(name, options.seed());
            TargetResult result = runner.run(target, options.seed(), options.inputs());
            results.add(result);
            System.out.printf("    done: %,d inputs at %,.0f/s, %d distinct anomal%s%n",
                    result.inputsExecuted(), result.inputsPerSecond(), result.anomalies().size(),
                    result.anomalies().size() == 1 ? "y" : "ies");
        }

        Path out = options.outputDir();
        Files.createDirectories(out);
        Path report = out.resolve("CAMPAIGN-RESULTS.md");
        Files.writeString(report, ReportWriter.render(results, options.seed(), options.timeoutMillis()));
        for (TargetResult result : results) {
            CorpusWriter.write(out.resolve("corpus"), result);
        }

        long distinct = results.stream().mapToLong(r -> r.anomalies().size()).sum();
        System.out.printf("%nWrote %s%n", report);
        System.out.printf("%,d distinct anomal%s across %d target(s)%n",
                distinct, distinct == 1 ? "y" : "ies", results.size());
    }

    /**
     * Parsed command line.
     *
     * @param targets target names to run
     * @param inputs inputs per target
     * @param seed fixes keys, seed corpus and the mutation stream
     * @param timeoutMillis per-input budget
     * @param outputDir where the report and corpus are written
     * @param minimize whether to shrink reproducers
     */
    record Options(List<String> targets, long inputs, long seed, long timeoutMillis, Path outputDir,
                   boolean minimize) {

        private static final long DEFAULT_INPUTS = 100_000;
        private static final long DEFAULT_SEED = 20260717;
        private static final long DEFAULT_TIMEOUT_MS = 5_000;

        static Options parse(String[] args) {
            List<String> targets = Targets.names();
            long inputs = DEFAULT_INPUTS;
            long seed = DEFAULT_SEED;
            long timeoutMillis = DEFAULT_TIMEOUT_MS;
            Path outputDir = Path.of("results");
            boolean minimize = true;

            for (String arg : args) {
                if (arg.startsWith("--targets=")) {
                    targets = parseTargets(value(arg));
                } else if (arg.startsWith("--inputs=")) {
                    inputs = positive(value(arg), "--inputs");
                } else if (arg.startsWith("--seed=")) {
                    seed = Long.parseLong(value(arg));
                } else if (arg.startsWith("--timeout-ms=")) {
                    timeoutMillis = positive(value(arg), "--timeout-ms");
                } else if (arg.startsWith("--out=")) {
                    outputDir = Path.of(value(arg));
                } else if (arg.equals("--no-minimize")) {
                    minimize = false;
                } else {
                    throw new IllegalArgumentException("unknown option: " + arg);
                }
            }
            return new Options(targets, inputs, seed, timeoutMillis, outputDir, minimize);
        }

        private static List<String> parseTargets(String value) {
            List<String> known = Targets.names();
            List<String> requested = List.of(value.split(","));
            for (String name : requested) {
                if (!known.contains(name)) {
                    throw new IllegalArgumentException(
                            "unknown target '" + name + "'; known: " + String.join(", ", known));
                }
            }
            return requested;
        }

        private static String value(String arg) {
            return arg.substring(arg.indexOf('=') + 1);
        }

        private static long positive(String value, String option) {
            long parsed = Long.parseLong(value);
            if (parsed <= 0) {
                throw new IllegalArgumentException(option + " must be positive, got " + parsed);
            }
            return parsed;
        }

        static String usage() {
            return """
                    usage: java -XX:-OmitStackTraceInFastThrow -jar pqc-fuzz.jar [options]
                      --targets=a,b     targets to run (default: all)
                      --inputs=N        inputs per target (default: %d)
                      --seed=N          campaign seed (default: %d)
                      --timeout-ms=N    per-input budget (default: %d)
                      --out=DIR         output directory (default: results)
                      --no-minimize     skip reproducer minimization

                    targets:
                    %s"""
                    .formatted(DEFAULT_INPUTS, DEFAULT_SEED, DEFAULT_TIMEOUT_MS,
                            String.join("\n", Targets.names().stream().map(n -> "  " + n).toList()));
        }
    }
}
