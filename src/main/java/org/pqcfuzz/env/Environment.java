package org.pqcfuzz.env;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.lang.management.ManagementFactory;
import java.util.List;

/**
 * The facts about the running JVM that a campaign result must carry to be reproducible, plus one
 * correctness check on the JVM's configuration.
 */
public final class Environment {

    /**
     * The HotSpot flag this harness depends on. By default the JIT applies the "fast throw"
     * optimization: once an implicit exception — {@code ArrayIndexOutOfBoundsException},
     * {@code NullPointerException} and friends — has been thrown often enough from the same site, it
     * stops constructing a new one and throws a preallocated instance <em>with an empty stack trace</em>.
     *
     * <p>That default is quietly disastrous here. Those exceptions are precisely the defect class this
     * study hunts, and {@link org.pqcfuzz.classify.AnomalySignature} identifies a defect by its top
     * stack frame. A campaign long enough to find a bug is more than long enough to make the JIT strip
     * the evidence, and the failure is silent: anomalies keep being counted, but they collapse into one
     * frameless signature and the reproducers point nowhere. The first few thousand hits would carry
     * traces and every one after would not, which is a worse outcome than an outright error.
     */
    public static final String STACK_TRACE_FLAG = "-XX:-OmitStackTraceInFastThrow";

    private Environment() {
    }

    /** Whether the JVM was started with {@link #STACK_TRACE_FLAG}. */
    public static boolean hasFullStackTraces() {
        List<String> args = ManagementFactory.getRuntimeMXBean().getInputArguments();
        return args.contains(STACK_TRACE_FLAG);
    }

    /** The BouncyCastle version under test, read from the provider rather than assumed. */
    public static String bouncyCastleVersion() {
        return String.valueOf(new BouncyCastleProvider().getVersionStr());
    }

    /** A one-line description of the JVM, recorded with every result. */
    public static String jvm() {
        return System.getProperty("java.vm.name")
                + " " + System.getProperty("java.version")
                + " (" + System.getProperty("java.vendor") + ")";
    }

    /** A one-line description of the host, recorded with every result. */
    public static String host() {
        return System.getProperty("os.name")
                + " " + System.getProperty("os.version")
                + " " + System.getProperty("os.arch")
                + ", " + Runtime.getRuntime().availableProcessors() + " cpus";
    }
}
