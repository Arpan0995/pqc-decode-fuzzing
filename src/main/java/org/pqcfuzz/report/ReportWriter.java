package org.pqcfuzz.report;

import org.pqcfuzz.classify.Outcome;
import org.pqcfuzz.env.Environment;
import org.pqcfuzz.mutate.Mutation;
import org.pqcfuzz.run.Anomaly;
import org.pqcfuzz.run.TargetResult;
import org.pqcfuzz.target.TargetKind;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Renders a campaign as the Markdown reported in {@code results/} (design §7): what ran, what the
 * outcomes were, how the pre-registered hypotheses fared, and the detail of any defect.
 */
public final class ReportWriter {

    private static final List<Outcome> COLUMNS = List.of(
            Outcome.OK, Outcome.REJECTED, Outcome.UNEXPECTED_EXCEPTION, Outcome.TIMEOUT, Outcome.ACCEPTED);

    private ReportWriter() {
    }

    /** Render the whole campaign. */
    public static String render(List<TargetResult> results, long seed, long timeoutMillis) {
        StringBuilder out = new StringBuilder();
        out.append("# Campaign Results — Fuzzing Java PQC Decode and Verify Paths\n\n");
        appendProvenance(out, seed, timeoutMillis);
        appendHeadline(out, results);
        appendSummary(out, results);
        appendHypotheses(out, results);
        appendPerTarget(out, results);
        return out.toString();
    }

    private static void appendProvenance(StringBuilder out, long seed, long timeoutMillis) {
        out.append("Generated ").append(Instant.now()).append(" by `FuzzCampaign`.\n\n");
        out.append("| Setting | Value |\n|---|---|\n");
        out.append("| BouncyCastle | ").append(Environment.bouncyCastleVersion()).append(" |\n");
        out.append("| JVM | ").append(Environment.jvm()).append(" |\n");
        out.append("| Host | ").append(Environment.host()).append(" |\n");
        out.append("| Campaign seed | `").append(seed).append("` |\n");
        out.append("| Per-input timeout | ").append(timeoutMillis).append(" ms |\n");
        out.append("| Full stack traces | ").append(Environment.hasFullStackTraces()
                ? "yes (`" + Environment.STACK_TRACE_FLAG + "`)"
                : "**NO — signatures may be unreliable, see below**").append(" |\n\n");
        if (!Environment.hasFullStackTraces()) {
            out.append("> **Warning.** This campaign ran without `").append(Environment.STACK_TRACE_FLAG)
                    .append("`, so the JIT may have replaced repeated implicit exceptions with"
                            + " preallocated, stackless ones. Any anomaly deduplication below is"
                            + " therefore suspect: distinct defects can collapse into one frameless"
                            + " signature. Re-run with the flag before reporting these numbers.\n\n");
        }
        out.append("Every result is reproducible from the campaign seed: it fixes the key pairs, the"
                + " seed corpus, and the mutation stream.\n\n");
    }

    /** Lead with the answer, since that is what a reader wants from a fuzzing study. */
    private static void appendHeadline(StringBuilder out, List<TargetResult> results) {
        long inputs = results.stream().mapToLong(TargetResult::inputsExecuted).sum();
        long distinct = results.stream().mapToLong(r -> r.anomalies().size()).sum();
        long exceptions = sum(results, Outcome.UNEXPECTED_EXCEPTION);
        long timeouts = sum(results, Outcome.TIMEOUT);
        // ACCEPTED means two different things, and conflating them would report a decoder's missing
        // length check as a break of the signature scheme — the single most alarming claim this report
        // could make, and it would be false. Split by the contract the target is held to.
        long forgeries = sumOfKind(results, Outcome.ACCEPTED, TargetKind.VERIFY);
        long wrongLengthAccepted = sum(results, Outcome.ACCEPTED) - forgeries;

        out.append("## Headline\n\n");
        out.append(String.format("%,d inputs across %d targets produced **%,d distinct anomal%s**.%n%n",
                inputs, results.size(), distinct, distinct == 1 ? "y" : "ies"));
        out.append("| Defect class | Inputs |\n|---|---:|\n");
        out.append(String.format("| Undocumented exception | %,d |%n", exceptions));
        out.append(String.format("| Timeout (potential DoS) | %,d |%n", timeouts));
        out.append(String.format("| Forgery accepted (verify path) | %,d |%n", forgeries));
        out.append(String.format("| Wrong-length encoding accepted (decoder) | %,d |%n%n",
                wrongLengthAccepted));
        if (distinct == 0) {
            out.append("No defects were found. This is an assurance result, not a proof of absence:"
                    + " it is bounded by the input budget above and by the blackbox mutation method"
                    + " (design §8). What makes it more than an untested claim is the BouncyCastle 1.84"
                    + " control (design §13): the same harness finds a real defect there, so a null"
                    + " result here reflects the library rather than a harness that cannot see.\n\n");
        }
    }

    private static void appendSummary(StringBuilder out, List<TargetResult> results) {
        out.append("## Summary\n\n");
        out.append("| Target | Kind | Nominal | Inputs | Inputs/s |");
        for (Outcome outcome : COLUMNS) {
            out.append(' ').append(label(outcome)).append(" |");
        }
        out.append(" Distinct |\n|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
        for (TargetResult r : results) {
            out.append("| `").append(r.targetName()).append("` | ").append(r.kind())
                    .append(" | ").append(r.nominalInputLength())
                    .append(" | ").append(String.format("%,d", r.inputsExecuted()))
                    .append(" | ").append(String.format("%,.0f", r.inputsPerSecond()));
            for (Outcome outcome : COLUMNS) {
                out.append(" | ").append(String.format("%,d", r.count(outcome)));
            }
            out.append(" | ").append(r.anomalies().size()).append(" |\n");
        }
        out.append("\nOutcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to"
                + " malformed input — verification returning false, or a documented exception"
                + " (`IllegalArgumentException`, `RuntimeCryptoException`, `CryptoException`)."
                + " `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class."
                + " Throughput is exploratory and host-specific; it also carries the cost of running"
                + " every input under a timeout watchdog.\n\n");

        int abandoned = results.stream().mapToInt(TargetResult::abandonedThreads).sum();
        if (abandoned > 0) {
            out.append("> **").append(abandoned).append(" thread(s) were abandoned to hung calls.**"
                    + " A hung call cannot be killed on the JVM, so those threads ran on alongside the"
                    + " rest of the campaign. Throughput figures after the first hang are contended and"
                    + " should not be compared against a clean run.\n\n");
        }
    }

    private static void appendHypotheses(StringBuilder out, List<TargetResult> results) {
        out.append("## Pre-registered hypotheses\n\n");
        out.append("Fixed in the design before any data was collected (§4), and scored here"
                + " mechanically from the counts above.\n\n");
        out.append("| | Verdict | Evidence |\n|---|---|---|\n");
        for (Hypothesis h : Hypotheses.evaluate(results)) {
            out.append("| **").append(h.id()).append("** | ")
                    .append(h.verdict() == Hypothesis.Verdict.SUPPORTED ? "supported" : "not supported")
                    .append(" | ").append(h.evidence()).append(" |\n");
        }
        out.append('\n');
        for (Hypothesis h : Hypotheses.evaluate(results)) {
            out.append("- **").append(h.id()).append("** — ").append(h.statement()).append('\n');
        }
        out.append("\nNote that **H2 predicts defects**, so for H2 alone \"supported\" is the finding and"
                + " \"not supported\" is the assurance result.\n\n");
    }

    private static void appendPerTarget(StringBuilder out, List<TargetResult> results) {
        out.append("## Per target\n\n");
        for (TargetResult r : results) {
            out.append("### `").append(r.targetName()).append("`\n\n");
            appendLengthSplit(out, r);
            appendMutationTable(out, r);
            appendAnomalies(out, r);
        }
    }

    /** The content-vs-length split: did anything break on inputs that were the right size? */
    private static void appendLengthSplit(StringBuilder out, TargetResult r) {
        long atNominal = r.outcomesAtNominalLength().values().stream().mapToLong(Long::longValue).sum();
        out.append(String.format("Of %,d inputs, %,d were exactly %d bytes — the correct length, so they"
                        + " passed any length check and reached the real parsing.%n%n",
                r.inputsExecuted(), atNominal, r.nominalInputLength()));
        if (atNominal == 0) {
            return;
        }
        out.append("| Correct-length outcome | Count |\n|---|---:|\n");
        for (Outcome outcome : COLUMNS) {
            long count = r.countAtNominalLength(outcome);
            if (count > 0) {
                out.append("| ").append(label(outcome)).append(" | ")
                        .append(String.format("%,d", count)).append(" |\n");
            }
        }
        out.append('\n');
    }

    private static void appendMutationTable(StringBuilder out, TargetResult r) {
        out.append("| Mutation |");
        for (Outcome outcome : COLUMNS) {
            out.append(' ').append(label(outcome)).append(" |");
        }
        out.append("\n|---|---:|---:|---:|---:|---:|\n");
        for (Mutation mutation : Mutation.values()) {
            Map<Outcome, Long> counts = r.outcomesByMutation().get(mutation);
            if (counts == null) {
                continue;
            }
            out.append("| ").append(mutation).append(" |");
            for (Outcome outcome : COLUMNS) {
                out.append(' ').append(String.format("%,d", counts.getOrDefault(outcome, 0L))).append(" |");
            }
            out.append('\n');
        }
        out.append('\n');
    }

    private static void appendAnomalies(StringBuilder out, TargetResult r) {
        if (!r.hasAnomalies()) {
            out.append("No anomalies.\n\n");
            return;
        }
        out.append("#### Anomalies\n\n");
        List<Anomaly> anomalies = r.anomalies();
        for (int i = 0; i < anomalies.size(); i++) {
            Anomaly a = anomalies.get(i);
            out.append(String.format("**%02d. %s — `%s`**%n%n", i, a.signature().outcome(),
                    a.signature().exceptionClass()));
            out.append("- Top frame: `").append(a.signature().topFrame()).append("`\n");
            if (!a.detail().isEmpty()) {
                out.append("- Message: `").append(a.detail()).append("`\n");
            }
            out.append("- Hits: ").append(String.format("%,d", a.count())).append('\n');
            out.append("- Found via: ").append(a.mutation()).append(" of seed ").append(a.seedIndex())
                    .append('\n');
            out.append("- Minimized reproducer: ").append(a.reproducer().length)
                    .append(" bytes (nominal ").append(r.nominalInputLength()).append("), saved under `")
                    .append("results/corpus/").append(r.targetName()).append("/`\n\n");
        }
    }

    private static String label(Outcome outcome) {
        return outcome == Outcome.UNEXPECTED_EXCEPTION ? "UNEXPECTED" : outcome.toString();
    }

    private static long sum(List<TargetResult> results, Outcome outcome) {
        return results.stream().mapToLong(r -> r.count(outcome)).sum();
    }

    private static long sumOfKind(List<TargetResult> results, Outcome outcome, TargetKind kind) {
        return results.stream().filter(r -> r.kind() == kind).mapToLong(r -> r.count(outcome)).sum();
    }
}
