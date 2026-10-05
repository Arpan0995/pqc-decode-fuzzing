# pqc-decode-fuzzing

**Does it reject cleanly?** A fuzzing study of the robustness of Java post-quantum **decode and verify**
paths - the first code an adversary reaches when a peer speaks PQC.

A server decapsulates a client's ML-KEM ciphertext; a client verifies a server's ML-DSA or SLH-DSA
signature; both parse encoded public keys from certificates and key-shares. These paths must be robust
to hostile bytes: a verify function should return "invalid" (never throw, hang, or accept a forgery),
and a decoder should fail predictably (a documented exception, never an `ArrayIndexOutOfBounds`,
`NegativeArraySize`, unbounded allocation, or a non-terminating loop). This project fuzzes those paths
in BouncyCastle and classifies every outcome.

## Status

Instrument built and validated; campaigns run. Nine BouncyCastle targets, two fuzzing methods, results in
[`results/`](results/). Since 2026-09-04 the same campaign also runs against the JDK's own ML-KEM and
ML-DSA providers (six `jdk-*` targets, JDK 24, 25 and 27-ea): see [`results/JDK-ARM.md`](results/JDK-ARM.md),
where the parse-only decoders turn out to accept a public key of any length and defer the size check to
the point of use. Since 2026-09-21 (design amendment A6) the campaigns are repeated under ten further
seeds and on BouncyCastle 1.86, the control is measured across seeds and operators, a graded synthetic
control measures how rare a fault each method can still find, and the coverage-guided harnesses run in
a corrected configuration: see [`results/a6/A6-RESULTS.md`](results/a6/A6-RESULTS.md). Since
2026-10-05 (design amendment A7) a hang control shows that the watchdog scores a planted non-terminating
input, a per-input comparison of the two arms shows that both implementations decide every shared input
the same way, and the coverage-guided harnesses run five trials per release: see
[`results/a7/A7-RESULTS.md`](results/a7/A7-RESULTS.md). The
pre-registered design - targets, outcome classification, hypotheses, and its seven amendments - is in
[`docs/EXPERIMENT-DESIGN.md`](docs/EXPERIMENT-DESIGN.md); **read that first.**

## The instrument finds real defects

BouncyCastle **1.84** ships a genuine defect that **1.85** fixes, and it is kept here as a **positive
control**: `MLDSAPublicKeyParameters` performs no length validation and accepts any encoding of 33 bytes
or more - a 1 MiB blob is a valid ML-DSA-65 public key as far as it is concerned - and using such a key
throws `ArrayIndexOutOfBoundsException` out of `Packing.unpackPublicKey`. ML-KEM and SLH-DSA validate
correctly in both versions; ML-DSA was the outlier. It is present in the **current, non-deprecated** API
(`org.bouncycastle.crypto.params`) that X.509 certificate parsing returns.

Running the identical harness against both versions is what makes a null result on 1.85 mean anything -
it answers *"would your harness have found a bug if there were one?"* with evidence instead of
assertion. Both fuzzing methods find it independently and converge on the same 33-byte input; Jazzer
takes under two seconds. Since 1.85 fixes it there is nothing to disclose: the value is in validating
the instrument. See design §13.

Reaching the defect takes a **valid signature and an invalid key**. ML-DSA checks the signature's own
structure before unpacking the public key, so a junk signature short-circuits and never touches the bad
key. Fuzzing the parse and verify entry points separately cannot construct that pairing, which is why
the composed targets exist (design §12, amendment A2).

## Approach

Two complementary methods over the same nine targets, sharing one `Classifier` so their results stay
comparable:

1. **Portable mutation campaign** (`FuzzCampaign`, pure Java, the workhorse behind the reported
   numbers): seed from valid encodings, apply structured mutations, drive each target under a per-input
   timeout, classify every outcome as `OK`, `REJECTED`, `UNEXPECTED_EXCEPTION`, `TIMEOUT`, or
   `ACCEPTED`, deduplicate anomalies by signature, and minimize each reproducer.
2. **Coverage-guided fuzzing** (Jazzer): JUnit5 `@FuzzTest` harnesses driving the same targets with
   libFuzzer-based JVM coverage feedback. The campaign generates inputs blind; Jazzer evolves them
   toward new coverage, so it can reach branches random mutation would find only by luck.
   The harnesses start from the same genuine seeds as the campaign, plus one over-length seed per
   target, and the library's classes are instrumented for coverage
   (`src/test/resources/junit-platform.properties`). Neither is the framework's default, and both
   matter: with an empty corpus and only the harness instrumented, a harness runs tens of millions of
   executions without ever passing the decoder's first length check
   ([`results/a6/A6-RESULTS.md`](results/a6/A6-RESULTS.md), section 6).

Every campaign replays from its seed, which fixes the key pairs, the seed corpus, and the mutation
stream.

## Targets

Six individual entry points (as pre-registered) plus three composed "parse then use" paths:

| Target | Kind | Input fuzzed |
|---|---|---|
| `ml-kem-768-decap` | decapsulate | ciphertext |
| `ml-kem-768-pubkey-parse` | decode | key encoding |
| `ml-kem-768-parse-encapsulate` | decode | key encoding |
| `ml-dsa-65-verify` | verify | signature |
| `ml-dsa-65-pubkey-parse` | decode | key encoding |
| `ml-dsa-65-parse-verify` | verify | key encoding |
| `slh-dsa-sha2-128f-verify` | verify | signature |
| `slh-dsa-sha2-128f-pubkey-parse` | decode | key encoding |
| `slh-dsa-sha2-128f-parse-verify` | verify | key encoding |

All drive `org.bouncycastle.crypto.{params,signers,generators,kems}` - the current API - never the
deprecated, identically-named `org.bouncycastle.pqc.crypto.*` classes (design §12, A1).

**JDK arm (design amendment A5, 2026-09-04).** Six further targets, `jdk-*`, drive the same entry points in
the JDK's own providers (JDK 24 and later: ML-KEM in `SunJCE`, ML-DSA in `SUN`; the JDK has no SLH-DSA).
The raw key is fuzzed, as above, and wrapped in a length-correct `SubjectPublicKeyInfo` because the JDK's
public API takes only X.509-encoded keys. ML-DSA keys and signatures are the BouncyCastle arm's own, so the
seed corpora, and hence the mutation streams, are byte-identical between the arms. The JDK targets use the
JDK's documented rejection rule (`InvalidKeySpecException`, `InvalidKeyException`, `SignatureException`,
`DecapsulateException`).

| Target | Kind | Input fuzzed |
|---|---|---|
| `jdk-ml-kem-768-decap` | decapsulate | ciphertext |
| `jdk-ml-kem-768-pubkey-parse` | decode | raw key, SPKI-wrapped |
| `jdk-ml-kem-768-parse-encapsulate` | decode | raw key, SPKI-wrapped |
| `jdk-ml-dsa-65-verify` | verify | signature |
| `jdk-ml-dsa-65-pubkey-parse` | decode | raw key, SPKI-wrapped |
| `jdk-ml-dsa-65-parse-verify` | verify | raw key, SPKI-wrapped |

## Running

```bash
mvn test                                    # unit tests + Jazzer regression mode
mvn test -Dbouncycastle.version=1.84        # the same suite against the control

# The mutation campaign
mvn package
java -XX:-OmitStackTraceInFastThrow -jar target/pqc-fuzz.jar --inputs=100000

# Coverage-guided fuzzing, one harness per JVM (expected to FAIL on 1.84 - that is the control working)
JAZZER_FUZZ=1 mvn test -Dtest='PqcDecodeFuzzTest#mlDsaParseAndVerify'
JAZZER_FUZZ=1 mvn test -Dtest='PqcDecodeFuzzTest#mlDsaParseAndVerify' -Dbouncycastle.version=1.84

# Regenerate the seed files the harnesses start from (run on JDK 24 or later to include the JDK targets)
java -cp target/pqc-fuzz.jar org.pqcfuzz.SeedExport src/test/resources/org/pqcfuzz/fuzz/PqcDecodeFuzzTestInputs

# The graded synthetic control (design amendment A6): K guarded bits
java -XX:-OmitStackTraceInFastThrow -jar target/pqc-fuzz.jar --targets=seeded-guard-k12 --out=/tmp/guard
JAZZER_FUZZ=1 mvn test -Dtest='SeededGuardFuzzTest#seededGuardK32'

# The hang control (design amendment A7): the same guard with a 20-second busy loop instead of an exception
java -XX:-OmitStackTraceInFastThrow -jar target/pqc-fuzz.jar --targets=seeded-hang-k12 --no-minimize --out=/tmp/hang

# Per-input comparison of the two arms (design amendment A7), JDK 24 or later
java -XX:-OmitStackTraceInFastThrow -cp target/pqc-fuzz.jar org.pqcfuzz.run.ArmDiff --out=/tmp/arm-diff

# Five two-minute coverage-guided trials of every BouncyCastle harness against one version (design amendment A7)
scripts/coverage-guided-trials.sh 1.85 /tmp/trials-bc185

# The JDK arm (design amendment A5): the same campaign against the JDK's own providers, JDK 24 or later
java -XX:-OmitStackTraceInFastThrow -jar target/pqc-fuzz.jar --targets=jdk --out=results/jdk25

# Coverage-guided fuzzing of the JDK targets. The two parse-only harnesses fail by design within
# seconds (the JDK accepts a wrong-length key, see A5) and are opt-in.
JAZZER_FUZZ=1 mvn test -Dtest=PqcDecodeFuzzTest -Dpqcfuzz.jdk.parse=true
```

`FuzzCampaign` options: `--targets=a,b`, `--inputs=N`, `--seed=N`, `--timeout-ms=N`, `--out=DIR`,
`--no-minimize`.

### Always pass `-XX:-OmitStackTraceInFastThrow`

Not optional, and it fails silently rather than loudly. By default HotSpot's "fast throw" optimization
replaces repeated implicit exceptions - `ArrayIndexOutOfBounds` and friends, i.e. exactly the defects
being hunted - with preallocated instances **carrying no stack trace**, once they get hot. Anomalies are
deduplicated by their top stack frame, so a campaign long enough to find a bug is more than long enough
for the JIT to strip the evidence: distinct defects collapse into one frameless signature and the
reproducers point nowhere. The build sets the flag for tests; `FuzzCampaign` warns if it is missing, and
so does the generated report.

## Toolchain

Java 21 (pinned OpenJDK 21); BouncyCastle `bcprov-jdk18on` **1.85** and **1.86** under test, **1.84** as
the control (`-Dbouncycastle.version=`; build each version from a clean tree, `mvn clean package`, or
the shaded jar keeps the previous version's classes); Jazzer (`jazzer-junit`) 0.22.1; Maven. Both BC versions expose the same
`org.bouncycastle.crypto.*` API, so one source tree targets either. Apple-Silicon runs are exploratory
for throughput; robustness findings are host-independent.

## Layout

```
docs/EXPERIMENT-DESIGN.md   Pre-registered design + amendments (read this first)
src/main/java/org/pqcfuzz/
  target/                   The nine BouncyCastle targets, the six JDK targets, the synthetic controls, the registry
  SeedExport.java           Writes each target's genuine inputs as seeds for the coverage-guided harnesses
  mutate/                   Mutation strategies and the generator
  classify/                 Outcome, the documented-rejection whitelist, anomaly signatures
  run/                      Campaign runner, per-input timeouts, reproducer minimization, the arm comparison
  report/                   Markdown report, hypothesis scoring, corpus writer
src/test/java/org/pqcfuzz/
  fuzz/                     Jazzer @FuzzTest harnesses
  control/                  The 1.84/1.85 control, as an executable specification
results/                    Campaign results and curated reproducers
scripts/                    Driver for the repeated coverage-guided trials (A7)
```

## License

Apache-2.0 (see `LICENSE`).
