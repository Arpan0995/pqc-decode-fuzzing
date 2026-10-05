# Experimental Design - Fuzzing the Decode and Verify Paths of Java Post-Quantum Cryptography

**Working title:** *Does It Reject Cleanly? A Fuzzing Study of the Robustness of Java Post-Quantum
Decode and Verify Paths*

**Author:** Arpan Sharma
**Status:** Design v0.4 - pre-registration of research questions, hypotheses, and method, with six
amendments recorded in §12. A1 to A4 were made during instrument construction, before any results
were collected or reported; A5 and A6 are dated extensions, each written before its own runs. §1 - §11
are otherwise as pre-registered.
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

**Version under test (recorded 2026-10-05).** The scaffold of 2026-07-16 (commit `d6a7528`) registered
BouncyCastle 1.84 as the version under test, in the heading of the target table and in the
reproducibility and threats sections. BouncyCastle 1.85 had reached Maven Central on 2026-07-12, four
days earlier. The construction-time smoke run found that the 1.84 ML-DSA public-key constructor accepts
an encoding of any length of 33 bytes or more and that 1.85 rejects wrong lengths; amendments A2 and A3
below were made so that the instrument could see that defect, 1.85 became the version under test, and
1.84 was retained as the positive control (§13). As first registered, the six targets and the original
oracle would have reported 1.84 clean. The switch was not recorded as an amendment at the time; it is
recorded here. The public history carries the scaffold and then a single commit (`93d207d`, 2026-07-17)
with the instrument, A1 to A4 and the 1.85 and 1.84 results together, so the timing of A1 to A4,
like that of A6 and A7, rests on this record and not on a public timestamp.

Four changes were made while building the instrument, before any results were collected, and a fifth
(A5) was added on 2026-09-04 to extend the study to a second implementation. Each is recorded here with
what prompted it, because a pre-registration that is quietly edited is worth nothing. None was made in
response to a campaign result; A1 to A4 came from reading the library and from a smoke run during
construction, and A5 records its own smoke finding before its campaigns ran. A sixth (A6) was added on
2026-09-21 and is of a different kind: it adds no target and changes no rule, it repeats the campaigns
under further seeds and on the current library release and measures how sensitive the instrument is.
It was written before the runs it describes, and its analyses are labelled exploratory because they
were designed after the results of A1 to A5 were known.

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

### A5 - A second implementation: the JDK's own providers (added 2026-09-04)

**When.** Unlike A1 to A4, this amendment was written after the BouncyCastle campaigns of 2026-07-17
were complete and published in `results/`, and before any JDK campaign was run. Nothing in A1 to A4
or in the BouncyCastle results changes.

**Change.** Six further targets, named `jdk-*`, drive the same entry points in the JDK's own
providers, which ship since JDK 24: ML-KEM in `SunJCE` (JEP 496) and ML-DSA in `SUN` (JEP 497). The
JDK has no SLH-DSA (as of 27-ea), so there are six targets, not nine:

| Target | Entry point (JDK) | Counterpart |
|---|---|---|
| `jdk-ml-kem-768-decap` | `KEM.Decapsulator.decapsulate(byte[])` | `ml-kem-768-decap` |
| `jdk-ml-kem-768-pubkey-parse` | `KeyFactory.generatePublic(X509EncodedKeySpec)` | `ml-kem-768-pubkey-parse` |
| `jdk-ml-kem-768-parse-encapsulate` | parse, then `KEM.newEncapsulator(...).encapsulate()` | `ml-kem-768-parse-encapsulate` |
| `jdk-ml-dsa-65-verify` | `Signature.verify(byte[])` after `update(msg)` | `ml-dsa-65-verify` |
| `jdk-ml-dsa-65-pubkey-parse` | `KeyFactory.generatePublic(X509EncodedKeySpec)` | `ml-dsa-65-pubkey-parse` |
| `jdk-ml-dsa-65-parse-verify` | parse, then `Signature.initVerify(key)` and `verify(sig)` | `ml-dsa-65-parse-verify` |

**Input wrapping.** The JDK's public API accepts a public key only as an X.509
`SubjectPublicKeyInfo`. The targets therefore fuzz the *raw* key, exactly as the BouncyCastle
targets do, and wrap it in a `SubjectPublicKeyInfo` whose DER lengths are recomputed for the payload
(`JdkPqc.spki`). The JDK's DER layer then passes whatever length the mutator produced, and the
decision about that length is left to the provider, which is the code under test. Wrapping with the
*original* header instead would make every length mutation fail in the DER layer for the wrong
reason, and would measure the DER parser, not the key decoder. Nominal input lengths are therefore
identical to the BouncyCastle arm (1184, 1952, 1088, 3309 bytes).

**Key material.** ML-DSA-65 keys and signatures are the BouncyCastle arm's own: the key pair is
derived from the campaign seed by the same generator, its raw public key is imported into the JDK
(which accepts it and re-encodes it identically), and signatures are made by BouncyCastle's
deterministic signer. The JDK verifies them. As a result the seed corpora of the five ML-DSA and
ML-KEM key or signature targets are byte-identical between the arms, and since the mutator is seeded
identically and the nominal lengths agree, the *i*-th input of a JDK campaign is the *i*-th input of
the BouncyCastle campaign with the same seed. The one exception is `jdk-ml-kem-768-decap`, whose key
pair the JDK generates itself from the seed (its generator draws from the supplied `SecureRandom`),
because JDK 24 cannot import BouncyCastle's PKCS#8 encoding of an ML-KEM private key (JDK 27 can).
Its seed ciphertexts are JDK encapsulations under a seeded random.

**Documented rejections for the JDK.** "Documented" is a property of the API under test, so the
classifier now asks the target (`FuzzTarget.isDocumentedRejection`). For the JDK targets the
whitelist is the set of checked exceptions these APIs declare for malformed input:
`InvalidKeySpecException` (`KeyFactory`), `InvalidKeyException` (`Signature.initVerify`,
`KEM.newEncapsulator`), `SignatureException` (`Signature.verify` on a structurally malformed
signature, the JDK's stated policy: invalid structure throws, a well-formed but wrong signature
returns false), and `DecapsulateException` (`Decapsulator.decapsulate` on a wrong-length
ciphertext). Anything else, `ProviderException` included, is `UNEXPECTED_EXCEPTION`. The
BouncyCastle rule is unchanged.

**Construction-time finding, recorded before the campaign.** As with A3, a smoke test while
building the targets found something. On JDK 24.0.2 and JDK 27-ea, `KeyFactory.generatePublic`
accepts a `SubjectPublicKeyInfo` whose inner ML-DSA-65 or ML-KEM-768 key has *any* length (0, 1, 33,
n-1, n+1 and 100,000 bytes were tried), and `CertificateFactory.generateCertificate` followed by
`getPublicKey()` returns such a key from a certificate. The size check runs only at use:
`Signature.initVerify` throws `InvalidKeyException("Incorrect public key size")` and
`KEM.newEncapsulator` throws `InvalidKeyException("Public key is not the correct size")`. The same
`KeyFactory` rejects a 31-byte Ed25519 key at parse time ("key length must be 32"). In the JDK
source, `NamedKeyFactory` builds a `NamedX509Key` from the raw bytes without a length check, and the
check lives in `ML_DSA.checkPublicKey`, reached from `NamedSignature.engineInitVerify`.

**Predictions, fixed here before running.** (1) `jdk-ml-dsa-65-pubkey-parse` and
`jdk-ml-kem-768-pubkey-parse` will score `ACCEPTED` on every wrong-length input, deduplicated to one
distinct anomaly each: the A3 outcome, the same class as the 1.84 control. (2) The composed targets
will score those inputs `REJECTED`, because the use-time check throws a documented exception; this
is the difference from 1.84, which threw `ArrayIndexOutOfBoundsException` at the same point. (3) H1,
H3 and H4 are expected to hold for the JDK arm; H2's "undocumented exception" clause is expected not
to be supported. (4) The results are expected to be identical on JDK 24 and JDK 27-ea.

**Limits.** The 1.84 control validates the instrument on BouncyCastle. For the JDK arm the
instrument's sensitivity to the `ACCEPTED` class is demonstrated by the finding above, which the
classifier scores exactly as A3 intends; its sensitivity to `UNEXPECTED_EXCEPTION` and `TIMEOUT` on
the JDK has no JDK-specific control, and the paper says so. The coverage-guided (Jazzer) method is
run on the JDK arm only if the Jazzer agent supports the JVM under test; otherwise the JDK results
are from the mutation campaign alone, and the report states which.

**Runs.** OpenJDK 25.0.2 (the current long-term-support release) is the primary JVM; JDK 24.0.2
(Amazon Corretto, the first release with these providers) and JDK 27-ea are the version-stability
checks. Same campaign parameters as the BouncyCastle arm: 100,000 inputs per target, seed
`20260717`, 5,000 ms per-input budget, `-XX:-OmitStackTraceInFastThrow`. Results are written to
`results/jdk25/`, `results/jdk24/` and `results/jdk27ea/`. The coverage-guided harnesses for the two
parse-only JDK targets fail by design on the empty input (the finding above) and are opt-in
(`-Dpqcfuzz.jdk.parse=true`); the finding itself is pinned by `JdkKeyLengthValidationTest`.

### A6 - Replication across seeds, the current release, and a sensitivity analysis (added 2026-09-21)

**When.** Written on 2026-09-21, after every campaign reported under A1 to A5 had been run and
written up, and before any run described here. Nothing in it can change a pre-registered verdict:
H1 to H4 are scored from the campaigns already recorded, and the runs below are reported beside
them, never in place of them. Because the questions were chosen with the earlier results in hand,
the analyses are exploratory and the paper labels them so.

**What prompted it.** Two fair objections to the study as it stood. A single seed says nothing about
how much of a result is luck, and a positive control that fires on a quarter of all inputs shows the
instrument can see an easy defect without saying how hard a defect it could still see.

**Runs.** (1) *Seeds.* The BouncyCastle campaign (nine targets) and the JDK campaign (six targets,
OpenJDK 25.0.2) are repeated under ten further seeds, `20260718` to `20260727`, with every other
parameter as before: 100,000 inputs per target, 5,000 ms per-input budget,
`-XX:-OmitStackTraceInFastThrow`. (2) *Current release.* BouncyCastle 1.86 was released on
2026-09-11; the nine-target campaign is run against it under the original seed and the ten further
seeds. (3) *Control.* The two ML-DSA targets that carry the 1.84 control
(`ml-dsa-65-pubkey-parse`, `ml-dsa-65-parse-verify`) are run against 1.84 under the same ten
further seeds. (4) *Coverage-guided time to detection.* The Jazzer harness for the composed ML-DSA
target is run against 1.84 ten times from an empty corpus and the time to the first failure is
recorded. [Erratum, recorded 2026-10-05: as run, this was both control harnesses, the parse-only and
the composed ML-DSA target, ten trials each, started from the four genuine seeds without the
over-length seed; see `results/a6/coverage-guided/control-trials.md`. The change was made when the
runs were set up, because a harness started from an empty corpus cannot generate a correctly sized
key within libFuzzer's default length limit, the failure that the corrected coverage-guided
configuration addresses, and it was not written into this amendment at the time.] (5) *A graded synthetic control* (added to this amendment on 2026-09-21, before it ran).
`seeded-guard-k<K>` is the library's ML-DSA-65 public-key decoder followed by one planted fault, an
`ArrayIndexOutOfBoundsException` that fires only when the input has the correct length, parses, and
holds the complement of the genuine key's bits in the *K* bits starting at byte 1000. Raising *K*
makes the same fault rarer without changing anything else. The mutation campaign runs it for
*K* = 1, 2, 4, 8, 12, 16, 24, 32 and 64 under the original seed and the ten further seeds; the
coverage-guided harness runs it for *K* = 8, 16, 32 and 64, five trials each from the genuine seed,
two minutes per trial. The target is synthetic, is labelled so wherever it is reported, is not
registered with the campaign's `bc`, `jdk` or `all` groups, and says nothing about any library: it
measures the instrument. Results are written to `results/a6/`.

**Measures.** For every distinct anomaly the report now records the position in the mutation stream
of the first input that reached it (`First seen at input`), so a defect's reachability is stated
as a number rather than implied by a hit count. Per seed: the outcome counts per target, the number
of distinct anomalies, and for the control the position of first detection and the share of inputs
that reach the defect, overall and per mutation operator. Across seeds: whether any seed changes a
verdict, and the range of the control's detection position.

**What a clean result bounds.** If a target shows zero anomalies in *n* inputs, the one-sided 95
percent upper confidence bound on the probability that one further input drawn from the same
mutation distribution produces an anomaly is 3/*n* (the rule of three). The bound is stated per
target and pooled, for the original campaign and for all seeds together. It is a statement about
this input distribution and this oracle, not about the code: a defect the mutation operators cannot
reach has probability zero under the distribution and is invisible to the bound, which is why the
control and the operator breakdown are reported beside it.

**Expectations, stated before the runs.** No seed changes a verdict on 1.85 or on the JDK. 1.86
behaves as 1.85 on all nine targets. The control is detected on every seed within the first
hundred inputs on both targets, by the operators that change the input length and by no operator
that preserves it. Coverage-guided fuzzing finds the control within seconds on every trial. On the synthetic control
the mutation campaign is expected to find the fault on every seed for small *K* and on none for
*K* of 32 and above, with the crossover somewhere between 8 and 16 bits; the coverage-guided
harness, which sees the comparison, is expected to find it at every *K*.

**Limits.** Ten seeds measure the stability of this instrument, not the absence of defects. The
sensitivity analysis characterizes one real defect of one class (a missing length check); it does
not show what the instrument would do with a defect that needs a specific value at a specific
offset, and the paper says so.

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


### A7 - A hang control, a per-input comparison of the arms, and repeated coverage-guided trials (added 2026-10-05)

**When.** Written on 2026-10-05, after the A6 results were written up and before any run described
here. Nothing here can change a pre-registered verdict; everything here is exploratory in the sense of
A6.

**What prompted it.** An outside reading of the manuscript asked three questions the record could not
answer. (1) H4 ("no input hangs") was scored "supported" by a watchdog never shown to detect a hang:
both controls end in an exception. (2) The statement that the two implementations reach the same final
decision on every shared input rested on equal aggregate counts, not on a per-input comparison. (3) The
coverage-guided arm reported one two-minute trial per harness and release, in a study that cites the
single-trial objection against others.

**Runs.** (1) *Hang control.* `seeded-hang-k<K>` is the library's ML-DSA-65 public-key decoder followed
by a planted busy loop of 20 seconds that runs only when the input has the correct length, parses, and
holds the complement of the genuine key's bits in the *K* bits starting at byte 1000: the guard of
`seeded-guard-k<K>`, unchanged. It is run at *K* = 12 under the eleven seeds of A6 with
`--no-minimize` (a timed-out input cannot be shrunk without re-running the hang) and every other
parameter as before. It is unregistered, like `seeded-guard-k<K>`, and never part of `bc`, `jdk` or
`all`. (2) *Per-input comparison.* `org.pqcfuzz.run.ArmDiff` drives the mutation stream of the original
seed, built exactly as the campaign builds it, through both members of each of the five target pairs
whose seed corpora are byte-identical between the arms, and records the pair of outcomes for every
input, on OpenJDK 25.0.2 with BouncyCastle 1.85. The decapsulation pair is excluded because its JDK key
pair is the JDK's own. (3) *Repeated coverage-guided trials.* Each of the nine BouncyCastle harnesses
is run five times for two minutes against 1.85 and five times against 1.86, in the corrected
configuration, from the committed seeds, each trial in a fresh JVM with no generated corpus carried
over; the libFuzzer status lines are kept so that the execution count at which coverage last grew can
be read off.

**Expectations.** (1) Under each seed the hang control records `TIMEOUT` inputs equal in number, and
equal in the position of the first, to the `UNEXPECTED_EXCEPTION` inputs that `seeded-guard-k12`
recorded under the same seed (ten seeds with one to five such inputs, one seed with none), and records
nothing else. (2) Zero disagreements on the three use-path pairs. On the two parse-only pairs the
disagreements are exactly the inputs BouncyCastle rejected and the JDK did not: 62,688 for the ML-KEM
key parse (29,956 wrong-length inputs the JDK scored `ACCEPTED` and 32,732 correct-length inputs it
scored `OK`) and 29,826 for the ML-DSA key parse (all wrong-length). (3) No anomaly in any trial; the
final edge count of each harness is the same in all five trials of a release; execution counts vary
with host load.

---

*Pre-registration: targets, the outcome classification, and hypotheses are fixed before data collection
so that a clean assurance result and a concrete defect finding carry equal weight. Amendments are
recorded in §12 rather than folded silently into the text above.*
