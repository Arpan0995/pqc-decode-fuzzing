# Amendment A6 Results - Replication, the Current Release, and Instrument Sensitivity

Design amendment A6 (`docs/EXPERIMENT-DESIGN.md`, section 12) was written on 2026-09-21, after every
campaign of A1 to A5 had been run and written up and before any run below. Its analyses are
exploratory: the questions were chosen with the earlier results in hand. They are reported beside the
pre-registered campaigns and cannot change a pre-registered verdict.

All mutation campaigns: 100,000 inputs per target, 5,000 ms per-input budget,
`-XX:-OmitStackTraceInFastThrow`. Seeds: the original `20260717` and ten further seeds `20260718` to
`20260727`. BouncyCastle arm on OpenJDK 21.0.9, JDK arm on OpenJDK 25.0.2, one host (macOS, aarch64).

## 1. Seeds and the current release

| Arm | Campaigns | Inputs | Anomalies |
|---|---:|---:|---|
| BouncyCastle 1.85, nine targets | 11 | 9,900,000 | 0 |
| BouncyCastle 1.86, nine targets | 11 | 9,900,000 | 0 |
| JDK 25.0.2, four use-path targets | 11 | 4,400,000 | 0 |
| JDK 25.0.2, two parse-only targets | 11 | 2,200,000 | `ACCEPTED` on every wrong-length key, every seed (the A5 behaviour) |

No seed changes a verdict on H1 to H4. For every target and every seed the outcome counts on 1.86 equal
those on 1.85. Reports: `bc185/seed-*/`, `bc186/seed-*/`, `jdk25/seed-*/` (the original-seed 1.85
campaign is `results/CAMPAIGN-RESULTS.md`).

Totals over eleven seeds, identical for 1.85 and 1.86:

| Target | OK | REJECTED | Anomalous |
|---|---:|---:|---:|
| `ml-kem-768-decap` | 770,250 | 329,750 | 0 |
| `ml-kem-768-pubkey-parse` | 409,069 | 690,931 | 0 |
| `ml-kem-768-parse-encapsulate` | 409,069 | 690,931 | 0 |
| `ml-dsa-65-verify` | 102 | 1,099,898 | 0 |
| `ml-dsa-65-pubkey-parse` | 770,104 | 329,896 | 0 |
| `ml-dsa-65-parse-verify` | 107 | 1,099,893 | 0 |
| `slh-dsa-sha2-128f-verify` | 127 | 1,099,873 | 0 |
| `slh-dsa-sha2-128f-pubkey-parse` | 769,600 | 330,400 | 0 |
| `slh-dsa-sha2-128f-parse-verify` | 148 | 1,099,852 | 0 |

## 2. The 1.84 control under eleven seeds

Reports: `control-bc184/seed-*/`. "First" is the new report field `First seen at input`, the position
in the mutation stream of the first input that reached the anomaly.

| | `ml-dsa-65-pubkey-parse` (`ACCEPTED`) | `ml-dsa-65-parse-verify` (`UNEXPECTED_EXCEPTION`) |
|---|---:|---:|
| Campaigns that found it | 11 of 11 | 11 of 11 |
| Anomalous inputs of 1,100,000 | 291,317 | 90,168 |
| Anomalous inputs per seed | 26,206 to 26,614 | 8,104 to 8,336 |
| First, median (range) | 3 (1 to 18) | 9 (1 to 25) |
| Minimized reproducer | 33 bytes | 33 bytes |
| Share of TRUNCATE inputs that reached it | 98.3% | 82.1% |
| Share of EXTEND inputs | 100% | 0% |
| Share of LENGTH_EDGE inputs | 66.6% | 0% |
| Share of the seven same-length operators' inputs | 0% | 0% |

The JDK parse-only behaviour under the same seeds: 29,707 to 30,177 accepted ML-DSA keys and 29,755 to
30,262 accepted ML-KEM keys per 100,000 inputs, first reached between input 1 and input 18, minimized
to the zero-byte key every time; every TRUNCATE, EXTEND and LENGTH_EDGE input and no same-length input.

## 3. Coverage-guided runs, corrected configuration

The harnesses now start from the genuine seeds the mutation campaign uses
(`src/test/resources/org/pqcfuzz/fuzz/*Inputs/`, written by `org.pqcfuzz.SeedExport`), plus one
over-length seed per target so that libFuzzer's inferred length limit exceeds the nominal length, and
the library's classes are instrumented for coverage (`jazzer.instrument` in
`src/test/resources/junit-platform.properties`). See section 6 for why. Two minutes per harness, one
JVM each, clean corpus. Log: `coverage-guided/main-batch.log`.

| Harness | 1.85 executions | 1.85 edges | 1.86 executions | 1.86 edges | Result |
|---|---:|---:|---:|---:|---|
| ML-KEM decapsulate | 2,941,906 | 252 | 2,804,391 | 255 | clean |
| ML-KEM key parse | 27,636,695 | 46 | 26,026,248 | 46 | clean |
| ML-KEM parse, encapsulate | 3,939,225 | 258 | 4,478,575 | 258 | clean |
| ML-DSA verify | 2,980,933 | 258 | 3,016,497 | 258 | clean |
| ML-DSA key parse | 24,014,124 | 54 | 25,518,774 | 54 | clean |
| ML-DSA parse, verify | 1,109,815 | 285 | 1,182,056 | 285 | clean |
| SLH-DSA verify | 74,697 | 196 | 90,806 | 193 | clean |
| SLH-DSA key parse | 32,633,121 | 32 | 33,921,103 | 32 | clean |
| SLH-DSA parse, verify | 82,675 | 221 | 104,423 | 218 | clean |
| Total | 95,413,191 | | 97,142,873 | | |

JDK arm (JDK 25.0.2): the four use-path harnesses ran 20,038,863, 19,400,268, 10,628,864 and
12,962,203 executions without an anomaly; the two parse-only harnesses fail on the empty input, the
first input the engine tries, in every run. Jazzer 0.22.1 cannot read Java 25 class files, so the JDK's
provider classes are not instrumented: on this arm the runs have seeds but no library coverage
feedback, and they count as a second mutation engine, not as coverage-guided evidence.

Control (`coverage-guided/control-trials.md`): from the genuine seeds alone, ten trials per harness
against 1.84 all fail within three seconds of wall time including JVM start, the composed harness on
a truncated key of 731 to 1,418 bytes (the same `ArrayIndexOutOfBoundsException`), the parse-only
harness on a wrong-length key of 986 to 1,896 bytes.

## 4. A graded synthetic control

`seeded-guard-k<K>` is the library's ML-DSA-65 public-key decoder followed by one planted fault that
fires only when the input has the correct length, parses, and holds the complement of the genuine
key's bits in the K bits starting at byte 1000. It is synthetic, is not registered with `bc`, `jdk` or
`all`, and says nothing about any library: it measures the instrument. Reports: `seeded-guard/k*/seed-*/`.

| K (bits) | Mutation campaigns that found it (of 11) | Median first input | Hits per campaign |
|---:|---:|---:|---:|
| 1 | 11 | 4 | 14,901 to 15,245 |
| 2 | 11 | 5 | 2,525 to 12,598 |
| 4 | 11 | 146 | 596 to 681 |
| 8 | 11 | 2,507 | 30 to 43 |
| 12 | 10 | 15,804 | 0 to 5 |
| 16 | 3 | 17,965 | 0 to 2 |
| 24 | 0 | - | 0 |
| 32 | 0 | - | 0 |
| 64 | 0 | - | 0 |

Guards of this kind are satisfied almost only by the RANDOM operator, about 10,000 inputs per
campaign, so the chance of detection is close to 1 - exp(-10000 / 2^K): 91% at K = 12, 14% at K = 16.

Coverage-guided (`coverage-guided/synthetic-control-trials.log`): found in 5 of 5 trials at each of
K = 8, 16, 32 and 64, every trial under eight seconds of wall time including JVM start. The engine
does not guess the value; its instrumentation reports the operands of the comparison.

## 5. What the malformed inputs reach

JaCoCo 0.8.15 over the 55 ML-KEM, ML-DSA and SLH-DSA classes of `bcprov-jdk18on-1.85`
(`coverage/genuine.csv`, `coverage/campaign.csv`; the released jar carries no line numbers, so the
counters are instructions and branches).

| Run | Instructions covered | Branches covered |
|---|---:|---:|
| Genuine inputs only (key generation, signing, encapsulation, one valid use per target) | 13,485 of 18,901 (71.3%) | 462 of 732 (63.1%) |
| Full campaign, original seed | 13,554 of 18,901 (71.7%) | 477 of 732 (65.2%) |

The 15 additional branches are in `Packing` (42 to 46 of 46), `MLKEMIndCpa` (+3), `MLDSAEngine` (+3),
`MLDSAPublicKeyParameters`, `MLKEMPublicKeyParameters`, `SLHDSAPublicKeyParameters`, `MLKEMExtractor`
and `SLHDSAEngine` (+1 each).

## 6. Correction: the first coverage-guided configuration tested nothing

Before A6 the harnesses used the framework's defaults: an empty starting corpus and coverage
instrumentation of the harness package only. `coverage-guided/old-configuration.txt` is that
configuration on `ml-dsa-65-pubkey-parse`: 28,777,142 executions in two minutes, coverage fixed at 16
edges, a corpus of one one-byte input, no library class instrumented, and libFuzzer's default
4,096-byte limit, which excludes a 17,088-byte SLH-DSA signature altogether. Those runs never left
the decoders' first length check. The coverage-guided figures reported earlier in
`results/JDK-ARM.md` and in the first preprint of the study came from that configuration and are
withdrawn; `coverage-guided/corrected-configuration.txt` shows the same harness with seeds loaded and
60 library classes instrumented. The mutation-campaign results were never affected.

## 7. A bound

Zero anomalies in n independent inputs bound the per-input anomaly rate under the campaign's input
distribution at 3/n with 95% confidence: 3.0e-5 for one target in one campaign, 2.7e-6 for one target
over eleven seeds, 3.0e-7 pooled over the nine targets of one release. The bound is about this input
distribution and this oracle, not about the code, which is why it is reported beside the controls.
