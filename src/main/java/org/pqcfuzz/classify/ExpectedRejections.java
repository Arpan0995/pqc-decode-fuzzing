package org.pqcfuzz.classify;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.RuntimeCryptoException;

/**
 * The pre-registered whitelist of exceptions that count as a <em>documented rejection</em> rather than
 * a defect. This whitelist is the line between {@link Outcome#REJECTED} and
 * {@link Outcome#UNEXPECTED_EXCEPTION}, so it is fixed up front and justified on the library's
 * documented semantics — not fitted to whatever the campaign happens to observe (design §8).
 *
 * <p>Three families are documented ways for a BouncyCastle primitive to refuse an argument:
 *
 * <ul>
 *   <li>{@link IllegalArgumentException} — the JDK-wide, and BouncyCastle's own, idiom for "this
 *       argument is malformed". A decoder saying "incorrect length" this way is behaving correctly.
 *   <li>{@link RuntimeCryptoException} — BouncyCastle's unchecked crypto-failure signal; its subclass
 *       {@code DataLengthException} is the documented response to a length mismatch.
 *   <li>{@link CryptoException} — BouncyCastle's checked crypto-failure signal, including
 *       {@code InvalidCipherTextException}.
 * </ul>
 *
 * <p>Everything else is unexpected by construction. Note that these families are disjoint from the
 * defects of interest: {@code ArrayIndexOutOfBoundsException} descends from
 * {@code IndexOutOfBoundsException}, {@code NegativeArraySizeException} and
 * {@code NullPointerException} descend directly from {@code RuntimeException}, and none of them are
 * {@code IllegalArgumentException}s. A bounds violation can therefore never be mistaken for a
 * documented rejection.
 */
public final class ExpectedRejections {

    private ExpectedRejections() {
    }

    /**
     * Whether {@code t} is a documented way to reject malformed input.
     *
     * <p>The cause chain is deliberately <em>not</em> consulted: a documented
     * {@code IllegalArgumentException} wrapping an {@code ArrayIndexOutOfBoundsException} is still a
     * clean rejection from the caller's point of view, and an undocumented exception is a defect
     * regardless of what it wraps.
     */
    public static boolean isDocumentedRejection(Throwable t) {
        return t instanceof IllegalArgumentException
                || t instanceof RuntimeCryptoException
                || t instanceof CryptoException;
    }
}
