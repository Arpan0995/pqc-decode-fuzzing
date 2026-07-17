package org.pqcfuzz.classify;

import org.pqcfuzz.target.FuzzTarget;
import org.pqcfuzz.target.TargetKind;

import java.util.Arrays;
import java.util.List;

/**
 * Turns what a target did into an {@link Outcome}, applying the pre-registered rules uniformly across
 * every target so that "defect" means one thing in this study (design §6).
 *
 * <p>Two judgements live here. Whether a throw was documented is delegated to
 * {@link ExpectedRejections}. Whether an acceptance was legitimate depends on the target's
 * {@link TargetKind}, because the kinds accept on different terms:
 *
 * <ul>
 *   <li>A {@link TargetKind#VERIFY} target claims authenticity when it accepts, so accepting anything
 *       but a genuine signature is a forgery — whatever the input's length.
 *   <li>A {@link TargetKind#DECODE} or {@link TargetKind#DECAPSULATE} target claims only well-formedness.
 *       Its wire format is a fixed length, so accepting a wrong-length input is accepting something
 *       malformed by definition. Contents are a different matter: these encodings are unstructured byte
 *       strings, so a correct-length input is well-formed however corrupt it is, and accepting it is
 *       correct.
 * </ul>
 *
 * <p>That length rule is what makes a missing validation visible. Without it, a decoder that never
 * checks length at all scores {@code OK} on every oversized input it swallows, and the instrument
 * reports perfect behaviour precisely where the library has none.
 */
public final class Classifier {

    private final TargetKind kind;
    private final List<byte[]> genuineInputs;
    private final int nominalInputLength;

    public Classifier(FuzzTarget target) {
        this.kind = target.kind();
        this.genuineInputs = List.copyOf(target.genuineInputs());
        this.nominalInputLength = target.nominalInputLength();
    }

    /**
     * Classify a call that returned normally.
     *
     * @param input the input that was fed to the target
     * @param accepted what the target returned
     */
    public Outcome classifyReturn(byte[] input, boolean accepted) {
        if (!accepted) {
            return Outcome.REJECTED;
        }
        if (kind == TargetKind.VERIFY) {
            return isGenuine(input) ? Outcome.OK : Outcome.ACCEPTED;
        }
        return input.length == nominalInputLength ? Outcome.OK : Outcome.ACCEPTED;
    }

    /** Classify a call that threw. */
    public Outcome classifyThrow(Throwable t) {
        return ExpectedRejections.isDocumentedRejection(t)
                ? Outcome.REJECTED
                : Outcome.UNEXPECTED_EXCEPTION;
    }

    /**
     * Whether the input is byte-for-byte one of the target's genuine inputs. Compared by value, not
     * identity: a mutation can perfectly well reconstruct a genuine input (truncating to full length,
     * say), and such an input verifying is correct behaviour, not a forgery.
     */
    private boolean isGenuine(byte[] input) {
        for (byte[] genuine : genuineInputs) {
            if (Arrays.equals(genuine, input)) {
                return true;
            }
        }
        return false;
    }
}
