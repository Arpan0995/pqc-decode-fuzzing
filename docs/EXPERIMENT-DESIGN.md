# Experimental Design — Fuzzing the Decode and Verify Paths of Java Post-Quantum Cryptography

**Working title:** *Does It Reject Cleanly? A Fuzzing Study of the Robustness of Java Post-Quantum
Decode and Verify Paths*

**Author:** Arpan Sharma
**Status:** Design draft v0.1 — pre-registration of research questions, hypotheses, and method. No
results yet.
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
published **fuzzing** assessment of the Java PQC decode/verify paths — the managed-runtime
implementations that front enterprise and government systems. This project provides one.

## 2. Targets (attacker-reachable entry points, BouncyCastle 1.84)

| Target | Entry point | Total-function expectation |
|---|---|---|
| ML-KEM decapsulation | `MLKEMExtractor.extractSecret(byte[])` | correct-length input never throws (implicit rejection); other input rejects cleanly |
| ML-KEM public-key parse | `new MLKEMPublicKeyParameters(params, byte[])` | documented exception on malformed, else valid |
| ML-DSA verify | `MLDSASigner.verifySignature(byte[])` after `update(msg)` | returns false on bad signature; never throws |
| ML-DSA public-key parse | `new MLDSAPublicKeyParameters(params, byte[])` | documented exception on malformed |
| SLH-DSA verify | `SLHDSASigner.verifySignature(msg, byte[])` | returns false on bad signature; never throws |
| SLH-DSA public-key parse | `new SLHDSAPublicKeyParameters(params, byte[])` | documented exception on malformed |

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
  inputs that trigger *undocumented* runtime exceptions (length/bounds handling on hostile encodings) —
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
   exception), `UNEXPECTED_EXCEPTION` (undocumented runtime exception — a defect), `TIMEOUT/HANG`,
   `ACCEPTED` (a forgery — a severe defect), or `OK` (valid input handled). It records a de-duplicated
   set of anomaly signatures (exception type + top stack frame) and saves minimal reproducing inputs to
   a corpus. This runs on any JVM without a native driver and produces the reported numbers.

The mutation campaign is the workhorse for reported results; the Jazzer harnesses provide the
coverage-guided, evolutionary complement and reproducibility with a standard fuzzer.

## 6. Outcome classification (the core instrument)

For each (target, input): `OK` (valid seed handled), `REJECTED` (the correct behavior for malformed
input — false or a documented `IllegalArgument`/rejection), `UNEXPECTED_EXCEPTION` (any other
`Throwable` — the primary defect class), `TIMEOUT` (exceeded the per-input budget — a potential
algorithmic-complexity DoS), or `ACCEPTED` (verify returned true for a non-genuine signature — a forgery
defect). Anomalies are de-duplicated by (outcome, exception class, top non-JDK stack frame) and each
unique signature is saved with a minimal reproducer.

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

- **Artifact:** an open-source fuzzing suite for Java PQC decode/verify paths — Jazzer harnesses plus a
  portable mutation campaign with outcome classification and a corpus — reusable for regression fuzzing.
- **Paper:** the first fuzzing robustness assessment of the NIST PQC decode/verify paths on the JVM,
  with an outcome taxonomy and any minimal reproducers.
  - Venues: USENIX WOOT, ICSE/ISSTA tool/short tracks, IEEE SecDev.

## 11. Non-goals

- Not a memory-safety study of native code (the JVM is memory-safe); the defects of interest are
  uncaught exceptions, hangs, unbounded allocation, and forgery acceptance.
- Not constant-time (covered by the side-channel project) or performance (covered elsewhere).
- Not a full protocol fuzzer (TLS state machine); we fuzz the cryptographic decode/verify primitives.

---

*Pre-registration: targets, the outcome classification, and hypotheses are fixed before data collection
so that a clean assurance result and a concrete defect finding carry equal weight.*
