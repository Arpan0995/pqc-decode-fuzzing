# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:43:54.261998Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| JDK PQC providers | none (the jdk-* targets need JDK 24 or later) |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260725` |
| Per-input timeout | 5000 ms |
| Full stack traces | yes (`-XX:-OmitStackTraceInFastThrow`) |

Every result is reproducible from the campaign seed: it fixes the key pairs, the seed corpus, and the mutation stream.

## Headline

100,000 inputs across 1 targets produced **1 distinct anomaly**.

| Defect class | Inputs |
|---|---:|
| Undocumented exception | 601 |
| Timeout (potential DoS) | 0 |
| Forgery accepted (verify path) | 0 |
| Wrong-length encoding accepted (decoder) | 0 |

## Summary

| Target | Kind | Nominal | Inputs | Inputs/s | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED | Distinct |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `seeded-guard-k4` | DECODE | 1952 | 100,000 | 28,681 | 69,324 | 30,075 | 601 | 0 | 0 | 1 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 0 inputs across 0 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | supported | 100,000 inputs across 1 decode target(s): 601 undocumented exception(s). |
| **H3** | not supported | No decapsulation target ran. |
| **H4** | supported | 100,000 input(s) across 1 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `seeded-guard-k4`

Of 100,000 inputs, 69,925 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,324 |
| UNEXPECTED | 601 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,994 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,977 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,186 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 9,868 | 0 | 6 | 0 | 0 |
| TRUNCATE | 0 | 10,083 | 0 | 0 | 0 |
| EXTEND | 0 | 9,957 | 0 | 0 | 0 |
| ZERO_FILL | 9,885 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,102 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,035 | 0 | 0 | 0 |
| RANDOM | 9,312 | 0 | 595 | 0 | 0 |

#### Anomalies

**00. UNEXPECTED_EXCEPTION — `java.lang.ArrayIndexOutOfBoundsException`**

- Top frame: `org.pqcfuzz.target.control.SeededGuardTarget.accepts:84`
- Message: `seeded control fault behind a 4-bit guard`
- Hits: 601
- First seen at input: 124
- Found via: RANDOM of seed 0
- Minimized reproducer: 1952 bytes (nominal 1952), saved under `results/corpus/seeded-guard-k4/`

