# Experimental Design - Fuzzing the Decode and Verify Paths of Java Post-Quantum Cryptography

**Working title:** *Does It Reject Cleanly? A Fuzzing Study of the Robustness of Java Post-Quantum
Decode and Verify Paths*

**Author:** Arpan Sharma
**Status:** Design v0.2 - pre-registration of research questions, hypotheses, and method, with four
amendments recorded in §12. The amendments were made during instrument construction, before any results
were collected or reported; §1 - §11 are otherwise as pre-registered.
**Repository:** `pqc-decode-fuzzing` (standalone).

---

## 1. Motivation and gap

Every network peer that speaks post-quantum cryptography must parse and verify attacker-controlled
bytes: a server decapsulates a client-supplied ML-KEM ciphertext, a client verifies a server-supplied
ML-DSA or SLH-DSA signature, and both parse encoded public keys from certificates and key-shares. These
**decode and verify paths are the first code an adversary reaches**, and their robustness is a
correctness- and availability-critical property distinct from the constant-time and performance
properties studied elsewhere in this program:

- A verify function must be *total*: for any input it should return "invalid," never throw an uncaught
  exception, never hang, and never accept a forgery. An unexpected exception on malformed input is at
  minimum a denial-of-service vector and at worst a parsing bug.
- A decode/parse function must fail *predictably*: it should reject malformed encodings with a
  documented exception, not an `ArrayIndexOutOfBoundsException`, `NegativeArraySizeException`,
  `NullPointerException`, an `OutOfMemoryError` from an attacker-chosen length, or a non-terminating
  loop.

Prior PQC testing focuses on known-answer test vectors (valid inputs) and side-channels. There is no
published **fuzzing** assessment of the Java PQC decode/verify paths - the managed-runtime
implementations that front enterprise and government systems. This project provides one.

## 2. Targets (attacker-reachable entry points)

All targets drive the **current** BouncyCastle API - `org.bouncycastle.crypto.{params,signers,generators,kems}`
 - and not the identically-named `org.bouncycastle.pqc.crypto.*` classes, which are deprecated as of 1.84
(amendment A1). This matters because `PublicKeyFactory` returns the former when it parses an X.509
certificate, so it is the code a real peer reaches.

**Individual entry points (as pre-registered):**

| Target | Entry point | Total-function expectation |
|---|---|---|
| ML-KEM decapsulation | `MLKEMExtractor.extractSecret(byte[])` | correct-length input never throws (implicit rejection); other input rejects cleanly |
| ML-KEM public-key parse | `new MLKEMPublicKeyParameters(params, byte[])` | documented exception on malformed, else valid |
| ML-DSA verify | `MLDSASigner.verifySignature(byte[])` after `update(msg)` | returns false on bad signature; never throws |
| ML-DSA public-key parse | `new MLDSAPublicKeyParameters(params, byte[])` | documented exception on malformed |
| SLH-DSA verify | `SLHDSASigner.verifySignature(msg, byte[])` | returns false on bad signature; never throws |
| SLH-DSA public-key parse | `new SLHDSAPublicKeyParameters(params, byte[])` | documented exception on malformed |

**Composed paths (amendment A2)** - parse an attacker-supplied public key, then *use* it. The fuzzed
input is the key encoding. These exist because a defect can live in the seam between two functions that
are each individually well-behaved, and the composition is what real peers actually perform:

| Target | Path | Who runs it on hostile bytes |
|---|---|---|
| ML-KEM parse + encapsulate | parse key → `MLKEMGenerator.generateEncapsulated` | a **server**, on the client's key_share, before any authentication |
| ML-DSA parse + verify | parse key → `MLDSASigner.verifySignature` | a **client**, on the key in the server's certificate |
| SLH-DSA parse + verify | parse key → `SLHDSASigner.verifySignature` | a **client**, on the key in the server's certificate |

## 3. Research questions

- **RQ1 (verify totality).** Do the ML-DSA and SLH-DSA verify paths reject malformed/adversarial
  signatures by returning false, or do any inputs cause an uncaught exception, hang, or acceptance?
- **RQ2 (decode predictability).** Do the public-key and ciphertext decoders reject malformed encodings
  with a *documented* exception, or do some inputs trigger undocumented runtime exceptions
  (`ArrayIndexOutOfBounds`, `NegativeArraySize`, `NullPointer`), unbounded allocation, or hangs?
- **RQ3 (ML-KEM decapsulation robustness).** Does `extractSecret` uphold its total contract for
  correct-length inputs, and how does it behave on wrong-length or structurally corrupt ciphertexts?
- **RQ4 (defect taxonomy and reproducibility).** For any anomalies found, what is the taxonomy
  (exception type, crashing input class), and can each be reduced to a minimal reproducing input?
- **RQ5 (throughput and coverage).** What input throughput does the campaign sustain, and (for the
  coverage-guided harness) what coverage of the target is reached?

## 4. Hypotheses (pre-registered)

- **H1.** The verify paths are *total*: no malformed signature causes an uncaught exception or forgery
  acceptance; all are rejected. (BouncyCastle is mature; a violation would be a notable finding.)
- **H2.** The decoders mostly reject with documented exceptions, but fuzzing surfaces at least a few
  inputs that trigger *undocumented* runtime exceptions (length/bounds handling on hostile encodings) -
  the usual yield of decoder fuzzing.
- **H3.** `extractSecret` never throws for correct-length (1088-byte) inputs (implicit rejection holds),
  but wrong-length inputs throw rather than reject.
- **H4.** No input causes a hang (non-termination / super-linear blow-up) within the time budget.

A confirmed H1/H4 with a clean taxonomy is a positive assurance result; any H2/H3 anomaly is a concrete
robustness finding. Both outcomes are publishable.

## 5. Methodology

Two complementary fuzzing approaches over the same targets:

1. **Coverage-guided fuzzing (Jazzer).** JUnit5 `@FuzzTest` harnesses driven by Jazzer (libFuzzer-based,
   JVM coverage feedback). Each harness feeds Jazzer-provided bytes to one target and asserts the
   total-function contract, letting Jazzer evolve inputs toward new coverage and toward contract
   violations. This is the reproducible, coverage-guided artifact.
2. **High-volume mutation campaign (portable, pure Java).** A self-contained engine that seeds from
   *valid* encodings (real ML-KEM ciphertexts/keys, ML-DSA/SLH-DSA signatures/keys), applies structured
   mutations (single/multi bit-flip, byte substitution, truncation, extension, zeroing, all-0xFF,
   length-field corruption, and fully random inputs), and drives each target under a per-input timeout.
   It **classifies every outcome** into: `REJECTED` (returned false / threw a documented/expected
   exception), `UNEXPECTED_EXCEPTION` (undocumented runtime exception - a defect), `TIMEOUT/HANG`,
   `ACCEPTED` (a forgery - a severe defect), or `OK` (valid input handled). It records a de-duplicated
   set of anomaly signatures (exception type + top stack frame) and saves minimal reproducing inputs to
   a corpus. This runs on any JVM without a native driver and produces the reported numbers.

The mutation campaign is the workhorse for reported results; the Jazzer harnesses provide the
coverage-guided, evolutionary complement and reproducibility with a standard fuzzer.

## 6. Outcome classification (the core instrument)

For each (target, input):

- `OK` - the target accepted something it may accept: a genuine signature, or a **correct-length**
  encoding (however corrupt its contents - these encodings are unstructured byte strings, so a
  right-length input is well-formed by definition).
- `REJECTED` - the correct response to malformed input: verify returned false, or the target threw a
  documented rejection. The whitelist is fixed up front and justified on BouncyCastle's documented
  semantics: `IllegalArgumentException`, `RuntimeCryptoException` (incl. `DataLengthException`), and
  `CryptoException` (incl. `InvalidCipherTextException`). These families are provably disjoint from the
  defects of interest - `ArrayIndexOutOfBoundsException` descends from `IndexOutOfBoundsException`, and
  `NegativeArraySizeException`/`NullPointerException` directly from `RuntimeException` - so a bounds
  violation can never be mistaken for a clean rejection.
- `UNEXPECTED_EXCEPTION` - any other `Throwable`. The primary defect class.
- `TIMEOUT` - exceeded the per-input budget: a potential algorithmic-complexity DoS.
- `ACCEPTED` - **the target accepted an input it should have refused.** Two forms: a verify path
  returning true for a non-genuine signature (a forgery), or a decoder accepting a **wrong-length**
  encoding (amendment A3).

Anomalies are de-duplicated by (outcome, exception class, top *informative* stack frame - skipping the
JDK and BouncyCastle's own `org.bouncycastle.util` array helpers, which report where a bad value was
used rather than where it was produced; amendment A4). Each unique signature is saved with a minimized
reproducer.

## 7. Metrics and reporting

Per target: inputs executed, throughput (inputs/s), outcome distribution, count and taxonomy of unique
anomaly signatures, and any timeouts/acceptances with minimal reproducers. A summary table plus the
saved corpus of interesting inputs are committed under `results/`.

## 8. Threats to validity

- **Blackbox vs coverage-guided.** The mutation campaign has no coverage feedback; the Jazzer harness
  supplies that. Reported anomaly *presence* is sound regardless; anomaly *absence* is bounded by the
  input budget and is reported as such (assurance, not proof).
- **Library/version specificity.** Findings are tied to BouncyCastle 1.84 and JDK 21; pinned and
  recorded. Any anomaly is reported with a minimal reproducer for responsible disclosure.
- **Exploratory host.** Throughput figures are host-specific; correctness/robustness findings are not.
- **Expected-exception whitelist.** The classification treats a specific, documented exception as
  `REJECTED`; the whitelist is defined up front and recorded, so "unexpected" is well-defined.

## 9. Reproducibility and disclosure

Pinned OpenJDK 21, BouncyCastle 1.84, Jazzer (version recorded). Deterministic seeds and a fixed input
budget make the campaign reproducible. Any genuine defect is minimized and reported to the BouncyCastle
maintainers before/at publication (responsible disclosure); the repository records reproducers.

## 10. Deliverables and target venues

- **Artifact:** an open-source fuzzing suite for Java PQC decode/verify paths - Jazzer harnesses plus a
  portable mutation campaign with outcome classification and a corpus - reusable for regression fuzzing.
- **Paper:** the first fuzzing robustness assessment of the NIST PQC decode/verify paths on the JVM,
  with an outcome taxonomy and any minimal reproducers.
  - Venues: USENIX WOOT, ICSE/ISSTA tool/short tracks, IEEE SecDev.

## 11. Non-goals

- Not a memory-safety study of native code (the JVM is memory-safe); the defects of interest are
  uncaught exceptions, hangs, unbounded allocation, and forgery acceptance.
- Not constant-time (covered by the side-channel project) or performance (covered elsewhere).
- Not a full protocol fuzzer (TLS state machine); we fuzz the cryptographic decode/verify primitives.

## 12. Amendments to the pre-registration

Four changes were made while building the instrument, before any results were collected. Each is
recorded here with what prompted it, because a pre-registration that is quietly edited is worth nothing.
None was made in response to a campaign result; all four came from reading the library and from a
smoke run during construction.

### A1 - Target the current API, not the deprecated `pqc.crypto` shim

**Change.** All targets moved from `org.bouncycastle.pqc.crypto.{mlkem,mldsa,slhdsa}` to
`org.bouncycastle.crypto.{params,signers,generators,kems}`.

**Why.** BouncyCastle deprecated the `pqc.crypto` spelling. The two APIs have identical class names and
signatures - both compile, and the difference is invisible in a diff - but `PublicKeyFactory` returns
the *current* classes when parsing an X.509 certificate. Since the study's claim is about the code real
peers reach, fuzzing the deprecated shim would have measured the wrong thing while looking correct.
A test (`TargetsTest#targetsUseTheModernApi`) now fails if any target reaches a `pqc.crypto` frame.

### A2 - Add three composed "parse then use" targets

**Change.** Added `ml-kem-768-parse-encapsulate`, `ml-dsa-65-parse-verify`,
`slh-dsa-sha2-128f-parse-verify`, bringing the target count to nine. The fuzzed input is the public-key
encoding.

**Why.** The pre-registered six fuzz each entry point in isolation, which cannot find a defect that lives
*between* two of them - and the one real defect in the corpus is exactly that shape. BouncyCastle 1.84's
ML-DSA decoder accepts a malformed key without complaint (so a parse-only target records `OK`), and the
`ArrayIndexOutOfBoundsException` only arrives once that key is used to verify. The composition is also
what real peers perform: nobody parses a certificate's key and then discards it.

Worth noting for anyone reproducing this: the defect needs a **valid signature and an invalid key**.
ML-DSA verification checks the signature's own structure before unpacking the public key, so a junk
signature is refused early and the bogus key is never touched. Probing with random bytes on both inputs
at once misses it.

### A3 - A decoder accepting a wrong-length encoding is `ACCEPTED`, not `OK`

**Change.** `ACCEPTED` generalized from "a verify path returned true for a non-genuine signature" to
"the target accepted an input it should have refused", which for a decoder means an input that is not
the length its wire format defines.

**Why.** The original rule scored *any* non-throwing parse as `OK`, so a decoder that never checks length
at all would be reported as flawless on every oversized input it swallowed - which is precisely what
happened on the 1.84 smoke run before the rule was fixed. These are fixed-length formats: a wrong length
is malformed by definition. Silently accepting one is worse than throwing, because the caller learns
nothing and the error surfaces later, further from its cause.

### A4 - Skip uninformative frames when deduplicating anomalies

**Change.** The signature's stack frame skips `org.bouncycastle.util.*` in addition to the JDK.

**Why.** The real 1.84 defect reports `org.bouncycastle.util.Arrays.copyOfRange` as its top non-JDK
frame - BouncyCastle's own thin wrapper over `System.arraycopy`, no more informative than the JDK method
it delegates to. Keying on it would merge every unrelated `copyOfRange` misuse in the library into a
single signature, defeating the purpose of deduplication. Skipping it lands on
`Packing.unpackPublicKey`: the code that computed the bad length, and the code a maintainer would fix.

### Effect on the hypotheses

H1 - H4 are unchanged and are scored mechanically from the counts (`org.pqcfuzz.report.Hypotheses`), so
they cannot be softened after the fact. A2 and A3 both *widen* what counts as a defect, which makes H1
and H2 harder to support, not easier.

## 13. The BouncyCastle 1.84 positive control

The study reports on **1.85** (current). **1.84** is retained as a positive control, because it carries a
real defect that 1.85 fixes: `MLDSAPublicKeyParameters` performs no length validation and accepts any
encoding of 33 bytes or more - a 1 MiB blob is a valid ML-DSA-65 public key as far as it is concerned -
and using such a key throws `ArrayIndexOutOfBoundsException` out of `Packing.unpackPublicKey`. ML-KEM and
SLH-DSA validate their lengths correctly in both versions; ML-DSA was the outlier.

This exists to answer the standard and correct objection to a null result: *how do you know your harness
would have found anything?* Running the identical harness against both versions answers it with evidence
rather than assertion - the defect must appear in 1.84 and not in 1.85. Both the mutation campaign and
the Jazzer harnesses find it independently, converging on the same 33-byte input.

It also delivers, cheaply, the differential-testing idea the project originally scoped against a second
implementation (liboqs via JNI): a cross-version differential needs no native code, no JNI, and no
second library's bugs to disentangle from BouncyCastle's.

Because 1.85 fixes the defect, there is nothing to disclose: the finding's value is in validating the
instrument, not in reporting a live vulnerability. Results are in `results/control-bc184/`, and the
behaviour is pinned as an executable specification in `MlDsaKeyLengthValidationTest`.

---

*Pre-registration: targets, the outcome classification, and hypotheses are fixed before data collection
so that a clean assurance result and a concrete defect finding carry equal weight. Amendments are
recorded in §12 rather than folded silently into the text above.*
