# Amendment A7 results: hang control, per-input arm comparison, repeated coverage-guided trials

Everything here was run on 2026-10-05 after amendment A7 was written into `docs/EXPERIMENT-DESIGN.md`.
The analyses are exploratory in the sense of A6; nothing changes a pre-registered verdict.

## 1. Hang control (`seeded-hang-k12`)

The hang control is the ML-DSA-65 public-key decoder of Bouncy Castle 1.85 followed by a 20-second busy loop
behind the 12-bit guard of `seeded-guard-k12`, run under the eleven seeds with `--no-minimize` (a timed-out
input cannot be shrunk without re-running the hang) and otherwise the A6 settings (100,000 inputs, 5,000 ms
budget, `-XX:-OmitStackTraceInFastThrow`, OpenJDK 21.0.9). Reports: `hang-control/k12/seed-*/CAMPAIGN-RESULTS.md`.

| Seed | Hang control: `TIMEOUT` inputs | First seen | Exception control: `UNEXPECTED` inputs | First seen | Hang inputs/s | Exception inputs/s |
|---|---:|---:|---:|---:|---:|---:|
| `20260717` | 3 | 9,243 | 3 | 9,243 | 4,861 | 28,746 |
| `20260718` | 3 | 11,566 | 3 | 11,566 | 5,116 | 30,269 |
| `20260719` | 4 | 26,353 | 4 | 26,353 | 4,136 | 14,911 |
| `20260720` | 3 | 5,987 | 3 | 5,987 | 5,389 | 14,952 |
| `20260721` | 1 | 69,134 | 1 | 69,134 | 12,559 | 29,257 |
| `20260722` | 5 | 17,965 | 5 | 17,965 | 3,428 | 28,758 |
| `20260723` | 0 | none | 0 | none | 35,569 | 28,667 |
| `20260724` | 4 | 13,642 | 4 | 13,642 | 3,985 | 28,771 |
| `20260725` | 1 | 48,074 | 1 | 48,074 | 11,190 | 14,748 |
| `20260726` | 2 | 20,557 | 2 | 20,557 | 7,104 | 29,431 |
| `20260727` | 2 | 5,221 | 2 | 5,221 | 7,233 | 29,770 |

**Expectation (1) met.** Under every seed the hang control records exactly as many `TIMEOUT` inputs as the exception
control recorded `UNEXPECTED_EXCEPTION` inputs (28 in all against 28), the first detection is the same input
position in every reaching seed, and seed `20260723`, which never reaches the guard, is clean for both. Every timed-out
call was abandoned to its own thread (the reports note the abandoned-thread count) and the campaign continued at a
fraction of its usual throughput while those threads spun. The watchdog therefore scores a hang on the mutation arm.
The coverage-guided engine's own timeout detection was not exercised.

## 2. Per-input comparison of the arms (`org.pqcfuzz.run.ArmDiff`)

Report: `arm-diff/seed-20260717/ARM-DIFF.md` (OpenJDK 25.0.2, Bouncy Castle 1.85, original seed, 100,000 inputs per pair).

| Pair | Disagreements | On wrong-length inputs | On correct-length inputs |
|---|---:|---:|---:|
| `ml-kem-768-pubkey-parse` / `jdk-ml-kem-768-pubkey-parse` | 62,688 of 100,000 | 29,956 | 32,732 |
| `ml-kem-768-parse-encapsulate` / `jdk-ml-kem-768-parse-encapsulate` | 0 of 100,000 | 0 | 0 |
| `ml-dsa-65-verify` / `jdk-ml-dsa-65-verify` | 0 of 100,000 | 0 | 0 |
| `ml-dsa-65-pubkey-parse` / `jdk-ml-dsa-65-pubkey-parse` | 29,826 of 100,000 | 29,826 | 0 |
| `ml-dsa-65-parse-verify` / `jdk-ml-dsa-65-parse-verify` | 0 of 100,000 | 0 | 0 |

**Expectation (2) met.** Zero disagreements on the three use-path pairs (300,000 inputs). On the parse-only pairs the
disagreements are exactly the inputs Bouncy Castle rejects at parse time and the JDK does not: 62,688 for the ML-KEM key
parse (29,956 wrong-length inputs the JDK scores `ACCEPTED` and 32,732 correct-length inputs it scores `OK` and refuses
only at `newEncapsulator`) and 29,826 for the ML-DSA key parse (all wrong-length).

## 3. Repeated coverage-guided trials

Five two-minute trials per harness against 1.85 and against 1.86 (90 trials), each in a fresh JVM from the committed
seeds with no generated corpus carried over, run from two git worktrees at commit `82d4221` with
`scripts/coverage-guided-trials.sh` on OpenJDK 21.0.9 (Jazzer 0.22.1). Per-trial libFuzzer status lines and a one-line
summary per trial are in `coverage-guided-trials/bc185/` and `coverage-guided-trials/bc186/`.

| Release | Harness | Trials | Executions (lowest to highest) | Edges at end (all trials) | Corpus | Limit at end (bytes) | Last coverage gain (executions, per trial) | Edges at INITED |
|---|---|---:|---:|---:|---:|---:|---|---|
| bc185 | `mlKemDecap` | 5 | 2,718,836 to 3,078,874 | 252 | 2 | 4,096 | 513, 913, 1,016, 754, 725 | 252 |
| bc186 | `mlKemDecap` | 5 | 2,748,555 to 3,056,830 | 255 | 2 | 4,096 | 1,022, 656, 1,123, 731, 595 | 255 |
| bc185 | `mlKemPublicKeyParse` | 5 | 27,240,847 to 28,756,150 | 46 | 3 | 4,096 | 1,074, 462, 1,374, 751, 709 | 44 |
| bc186 | `mlKemPublicKeyParse` | 5 | 27,030,786 to 28,601,956 | 46 | 3 | 4,096 | 859, 625, 778, 679, 843 | 44 |
| bc185 | `mlKemParseAndEncapsulate` | 5 | 4,014,358 to 4,566,933 | 258 | 17 to 20 | 4,096 | 3,215,073, 25,223, 2,601,331, 1,696,610, 62,067 | 251 |
| bc186 | `mlKemParseAndEncapsulate` | 5 | 4,063,013 to 4,703,790 | 258 | 18 to 20 | 4,096 | 2,635,708, 110,190, 1,935,965, 507,892, 42,754 | 251 |
| bc185 | `mlDsaVerify` | 5 | 2,785,895 to 3,064,574 | 258 | 37 to 44 | 4,096 | 623,849, 586,675, 2,410,854, 2,979,962, 857,358 | 249 |
| bc186 | `mlDsaVerify` | 5 | 2,854,906 to 3,081,774 | 258 | 40 to 42 | 4,096 | 2,034,424, 1,871,309, 557,494, 1,858,779, 2,849,756 | 249 |
| bc185 | `mlDsaPublicKeyParse` | 5 | 21,563,071 to 22,652,745 | 60 | 2 | 4,096 | 829, 266, 1,122, 714, 770 | 60 |
| bc186 | `mlDsaPublicKeyParse` | 5 | 21,416,508 to 22,563,418 | 60 | 2 | 4,096 | 524, 603, 646, 673, 743 | 60 |
| bc185 | `mlDsaParseAndVerify` | 5 | 1,148,765 to 1,196,920 | 285 | 14 to 17 | 4,096 | 1,141,640, 705,988, 551,944, 355,577, 800,630 | 285 |
| bc186 | `mlDsaParseAndVerify` | 5 | 1,164,743 to 1,181,245 | 285 | 11 to 17 | 4,096 | 82,560, 1,154,472, 263,488, 163,561, 992,193 | 285 |
| bc185 | `slhDsaVerify` | 5 | 74,439 to 79,947 | 196 | 18 to 21 | 17,152 | 8,503, 10,284, 9,762, 8,250, 21,408 | 196 |
| bc186 | `slhDsaVerify` | 5 | 89,528 to 95,426 | 193 | 19 to 20 | 17,152 | 10,468, 7,685, 21,656, 10,841, 11,135 | 193 |
| bc185 | `slhDsaPublicKeyParse` | 5 | 33,304,560 to 34,905,568 | 32 | 2 | 4,096 | 388, 339, 222, 240, 172 | 32 |
| bc186 | `slhDsaPublicKeyParse` | 5 | 32,977,832 to 34,200,245 | 32 | 2 | 4,096 | 501, 249, 88, 347, 485 | 32 |
| bc185 | `slhDsaParseAndVerify` | 5 | 79,228 to 85,071 | 221 | 18 to 20 | 856/874/892/901 | 9,853, 78,523, 61,244, 5,163, 3,165 | 221 |
| bc186 | `slhDsaParseAndVerify` | 5 | 94,517 to 102,448 | 218 | 19 to 22 | 1,018/1,057/1,077/1,087/1,097 | 1,916, 16,637, 50,526, 7,164, 30,734 | 218 |

**Totals.** 476,972,227 executions on 1.85 and 476,471,148 on 1.86 (953,443,375 in all); no anomaly in any of the 90 trials.

**Expectation (3) met.** No anomaly; the final edge count of each harness is the same in all five trials of a release;
execution counts vary with host load (two trials ran side by side on the same host). The last coverage gain on the
verify and composed harnesses came after at most 3,215,073 executions (ML-KEM composed, 1.85) and on the parse-only
harnesses within the first 1,374; the remaining minutes added executions but no edges.

**Note on the 21 September single runs** (`../a6/coverage-guided/main-batch.log`): they agree with these trials except that
`mlDsaPublicKeyParse` reported 54 covered edges then (54 at INITED as well) and 60 in every trial here (60 at INITED),
so the difference is present from the first execution of the seeds and is not something fuzzing reached.
The single-run values stay in `results/a6`; the paper's Table 5 now reports the five trials.
