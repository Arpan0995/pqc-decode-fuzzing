package org.pqcfuzz;

import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.Targets;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes each target's genuine inputs as seed files for the coverage-guided harnesses (design
 * amendment A6).
 *
 * <p>A coverage-guided fuzzer that starts from an empty corpus spends its budget rediscovering the
 * length of the input: nothing it generates passes the decoder's first check, so it never reaches the
 * parsing behind it, and libFuzzer's default 4096-byte limit rules out a 17088-byte SLH-DSA signature
 * altogether. Seeding with the same genuine inputs the mutation campaign starts from puts both methods
 * on an equal footing. One over-length seed per target raises libFuzzer's inferred length limit above
 * the nominal length, so inputs that are too long stay reachable as well.
 *
 * <pre>
 *   java -cp target/pqc-fuzz.jar org.pqcfuzz.SeedExport \
 *       src/test/resources/org/pqcfuzz/fuzz/PqcDecodeFuzzTestInputs
 * </pre>
 */
public final class SeedExport {

    /** Bytes appended to the over-length seed. */
    private static final int OVER_LENGTH = 64;

    private static final long SEED = 20260717L;

    /** Target name to the name of its {@code @FuzzTest} method, which is the directory Jazzer reads. */
    private static final Map<String, String> METHODS = new LinkedHashMap<>();

    static {
        METHODS.put("ml-kem-768-decap", "mlKemDecap");
        METHODS.put("ml-kem-768-pubkey-parse", "mlKemPublicKeyParse");
        METHODS.put("ml-kem-768-parse-encapsulate", "mlKemParseAndEncapsulate");
        METHODS.put("ml-dsa-65-verify", "mlDsaVerify");
        METHODS.put("ml-dsa-65-pubkey-parse", "mlDsaPublicKeyParse");
        METHODS.put("ml-dsa-65-parse-verify", "mlDsaParseAndVerify");
        METHODS.put("slh-dsa-sha2-128f-verify", "slhDsaVerify");
        METHODS.put("slh-dsa-sha2-128f-pubkey-parse", "slhDsaPublicKeyParse");
        METHODS.put("slh-dsa-sha2-128f-parse-verify", "slhDsaParseAndVerify");
        METHODS.put("jdk-ml-kem-768-decap", "jdkMlKemDecap");
        METHODS.put("jdk-ml-kem-768-pubkey-parse", "jdkMlKemPublicKeyParse");
        METHODS.put("jdk-ml-kem-768-parse-encapsulate", "jdkMlKemParseAndEncapsulate");
        METHODS.put("jdk-ml-dsa-65-verify", "jdkMlDsaVerify");
        METHODS.put("jdk-ml-dsa-65-pubkey-parse", "jdkMlDsaPublicKeyParse");
        METHODS.put("jdk-ml-dsa-65-parse-verify", "jdkMlDsaParseAndVerify");
    }

    private SeedExport() {
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("usage: SeedExport <inputs-directory>");
            System.exit(2);
        }
        Path root = Path.of(args[0]);
        for (Map.Entry<String, String> entry : METHODS.entrySet()) {
            FuzzTarget target;
            try {
                target = Targets.create(entry.getKey(), SEED);
            } catch (RuntimeException | LinkageError e) {
                System.out.printf("skipped %s (%s)%n", entry.getKey(), e);
                continue;
            }
            Path dir = root.resolve(entry.getValue());
            Files.createDirectories(dir);
            List<byte[]> seeds = target.seedCorpus();
            for (int i = 0; i < seeds.size(); i++) {
                Files.write(dir.resolve("seed-" + i), seeds.get(i));
            }
            byte[] first = seeds.get(0);
            byte[] longer = new byte[first.length + OVER_LENGTH];
            System.arraycopy(first, 0, longer, 0, first.length);
            Files.write(dir.resolve("seed-over-length"), longer);
            System.out.printf("%s: %d seed(s) of %d bytes, one of %d%n",
                    entry.getKey(), seeds.size(), first.length, longer.length);
        }
    }
}
