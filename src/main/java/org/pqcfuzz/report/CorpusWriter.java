package org.pqcfuzz.report;

import org.pqcfuzz.run.Anomaly;
import org.pqcfuzz.run.TargetResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

/**
 * Saves each distinct defect's reproducer to disk: the raw bytes, and a note saying what they do.
 *
 * <p>The raw {@code .bin} is the artifact that matters — it is what a maintainer feeds back to the
 * library to see the crash for themselves, and it is what makes a disclosure actionable rather than
 * anecdotal. The companion {@code .txt} exists because a bare blob is unreadable six months later, or
 * by anyone who did not run the campaign.
 */
public final class CorpusWriter {

    /** Beyond this, a hexdump stops being something a human reads. */
    private static final int HEX_PREVIEW_BYTES = 256;

    private CorpusWriter() {
    }

    /**
     * Write every anomaly's reproducer under {@code corpusRoot/<target>/}.
     *
     * @return the directory written, or empty-handed if the target had no anomalies
     */
    public static Path write(Path corpusRoot, TargetResult result) throws IOException {
        Path dir = corpusRoot.resolve(result.targetName());
        if (!result.hasAnomalies()) {
            return dir;
        }
        Files.createDirectories(dir);
        List<Anomaly> anomalies = result.anomalies();
        for (int i = 0; i < anomalies.size(); i++) {
            Anomaly anomaly = anomalies.get(i);
            String stem = stemFor(i, anomalies.get(i));
            Files.write(dir.resolve(stem + ".bin"), anomaly.reproducer());
            Files.writeString(dir.resolve(stem + ".txt"), describe(result, anomaly),
                    StandardCharsets.UTF_8);
        }
        return dir;
    }

    /**
     * A filename naming the defect: {@code 00-UNEXPECTED_EXCEPTION-ArrayIndexOutOfBoundsException}, or
     * just {@code 00-ACCEPTED} for the outcomes that carry no exception to name.
     */
    private static String stemFor(int index, Anomaly anomaly) {
        String exceptionClass = anomaly.signature().exceptionClass();
        String stem = String.format("%02d-%s", index, anomaly.signature().outcome());
        return exceptionClass.equals("-") ? stem : stem + "-" + simpleName(exceptionClass);
    }

    private static String describe(TargetResult result, Anomaly anomaly) {
        StringBuilder out = new StringBuilder();
        out.append("target:      ").append(result.targetName()).append('\n');
        out.append("outcome:     ").append(anomaly.signature().outcome()).append('\n');
        out.append("exception:   ").append(anomaly.signature().exceptionClass()).append('\n');
        out.append("message:     ").append(anomaly.detail()).append('\n');
        out.append("top frame:   ").append(anomaly.signature().topFrame()).append('\n');
        out.append("hits:        ").append(anomaly.count()).append('\n');
        out.append("found via:   ").append(anomaly.mutation())
                .append(" of seed ").append(anomaly.seedIndex()).append('\n');
        out.append("input size:  ").append(anomaly.reproducer().length).append(" bytes (nominal ")
                .append(result.nominalInputLength()).append(")\n");
        out.append('\n');
        out.append(hexPreview(anomaly.reproducer()));
        if (!anomaly.stackTrace().isEmpty()) {
            out.append('\n').append(anomaly.stackTrace());
        }
        return out.toString();
    }

    private static String hexPreview(byte[] input) {
        StringBuilder out = new StringBuilder("input (hex");
        int shown = Math.min(input.length, HEX_PREVIEW_BYTES);
        if (shown < input.length) {
            out.append(", first ").append(shown).append(" of ").append(input.length).append(" bytes");
        }
        out.append("):\n");
        HexFormat hex = HexFormat.of();
        for (int offset = 0; offset < shown; offset += 32) {
            int end = Math.min(offset + 32, shown);
            out.append(String.format("  %04x  ", offset))
                    .append(hex.formatHex(input, offset, end))
                    .append('\n');
        }
        if (input.length == 0) {
            out.append("  (empty)\n");
        }
        return out.toString();
    }

    private static String simpleName(String className) {
        int dot = className.lastIndexOf('.');
        return dot < 0 ? className : className.substring(dot + 1);
    }
}
