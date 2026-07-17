package org.pqcfuzz.classify;

import java.util.List;

/**
 * The identity of an anomaly, used to collapse many crashing inputs into the few underlying defects
 * (design §6). A campaign that flips bits at random will hit the same bad line thousands of times; what
 * a maintainer needs is the line, once, with one input that reaches it.
 *
 * <p>The signature is (outcome, exception class, top non-JDK frame). The frame is the deduplication
 * key that matters: the exception class alone would merge two unrelated bounds bugs, while the full
 * stack would split one bug across every path that reaches it.
 *
 * @param outcome the anomalous outcome
 * @param exceptionClass the thrown class name, or {@code "-"} for outcomes with no exception
 * @param topFrame the first stack frame outside the JDK — the library code responsible — or {@code "-"}
 */
public record AnomalySignature(Outcome outcome, String exceptionClass, String topFrame) {

    private static final String NONE = "-";

    /** Signature of an outcome carrying no exception ({@link Outcome#TIMEOUT}, {@link Outcome#ACCEPTED}). */
    public static AnomalySignature of(Outcome outcome) {
        return new AnomalySignature(outcome, NONE, NONE);
    }

    /** Signature of a thrown anomaly. */
    public static AnomalySignature of(Outcome outcome, Throwable t) {
        return new AnomalySignature(outcome, t.getClass().getName(), topNonJdkFrame(t));
    }

    /**
     * Frame prefixes that never identify a defect, only the place it became visible.
     *
     * <p>The JDK entries are obvious: a bounds violation surfaces in {@code java.lang.System.arraycopy},
     * which is the same frame for every such bug in existence.
     *
     * <p>{@code org.bouncycastle.util} is here for exactly the same reason, and observation is what put
     * it there. The real ML-DSA defect in 1.84 reports {@code org.bouncycastle.util.Arrays.copyOfRange}
     * as its top non-JDK frame — BouncyCastle's own thin wrapper over {@code System.arraycopy}, no more
     * informative than the JDK method it delegates to. Keying on it would merge every unrelated
     * {@code copyOfRange} misuse across the whole library into one signature, which is precisely the
     * over-merging this class exists to prevent. Skipping it lands on
     * {@code Packing.unpackPublicKey} — the code that computed the bad length, and the code a
     * maintainer would fix.
     *
     * <p>The rule generalizes: skip frames that <em>report</em> a bad value, keep the first that
     * <em>produced</em> one.
     */
    private static final List<String> UNINFORMATIVE_FRAMES =
            List.of("java.", "jdk.", "sun.", "org.bouncycastle.util.");

    /** The first frame that identifies the code responsible, rather than the code that noticed. */
    private static String topNonJdkFrame(Throwable t) {
        for (StackTraceElement frame : t.getStackTrace()) {
            if (isInformative(frame.getClassName())) {
                return format(frame);
            }
        }
        // Nothing informative: either an all-JDK trace, or the JIT stripped it (see Environment).
        StackTraceElement[] trace = t.getStackTrace();
        return trace.length == 0 ? NONE : format(trace[0]);
    }

    private static boolean isInformative(String className) {
        return UNINFORMATIVE_FRAMES.stream().noneMatch(className::startsWith);
    }

    /**
     * Render a frame, omitting the line number when there is none. BouncyCastle ships without debug
     * information, so every frame in a release jar reports line {@code -1}; printing it would put a
     * meaningless {@code :-1} on the end of every signature in the results.
     */
    private static String format(StackTraceElement frame) {
        String location = frame.getClassName() + "." + frame.getMethodName();
        return frame.getLineNumber() > 0 ? location + ":" + frame.getLineNumber() : location;
    }

    @Override
    public String toString() {
        return outcome + " / " + exceptionClass + " @ " + topFrame;
    }
}
