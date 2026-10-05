# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:27:39.157858Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 25.0.2 (Homebrew) |
| JDK PQC providers | ML-DSA: SUN, ML-KEM: SunJCE |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260725` |
| Per-input timeout | 5000 ms |
| Full stack traces | yes (`-XX:-OmitStackTraceInFastThrow`) |

Every result is reproducible from the campaign seed: it fixes the key pairs, the seed corpus, and the mutation stream.

## Headline

600,000 inputs across 6 targets produced **2 distinct anomalies**.

| Defect class | Inputs |
|---|---:|
| Undocumented exception | 0 |
| Timeout (potential DoS) | 0 |
| Forgery accepted (verify path) | 0 |
| Wrong-length encoding accepted (decoder) | 60,083 |

## Summary

| Target | Kind | Nominal | Inputs | Inputs/s | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED | Distinct |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `jdk-ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 20,876 | 70,167 | 29,833 | 0 | 0 | 0 | 0 |
| `jdk-ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 26,086 | 69,992 | 0 | 0 | 0 | 30,008 | 1 |
| `jdk-ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 20,261 | 11 | 99,989 | 0 | 0 | 0 | 0 |
| `jdk-ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 19,287 | 69,925 | 0 | 0 | 0 | 30,075 | 1 |
| `jdk-ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 20,996 | 37,103 | 62,897 | 0 | 0 | 0 | 0 |
| `jdk-ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 13,276 | 7 | 99,993 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 200,000 inputs across 2 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 300,000 inputs across 3 decode target(s): 0 undocumented exception(s). Separately, 60,083 wrong-length encoding(s) were silently **accepted** — a decoder defect that H2 did not anticipate, since it fails without throwing. |
| **H3** | supported | 70,167 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 600,000 input(s) across 6 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `jdk-ml-kem-768-decap`

Of 100,000 inputs, 70,167 were exactly 1088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,167 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,022 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,022 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,959 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,041 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,907 | 0 | 0 | 0 |
| EXTEND | 0 | 9,926 | 0 | 0 | 0 |
| ZERO_FILL | 10,002 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,200 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,000 | 0 | 0 | 0 |
| RANDOM | 9,921 | 0 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-kem-768-pubkey-parse`

Of 100,000 inputs, 69,992 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,992 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,855 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,059 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,801 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,062 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 0 | 0 | 0 | 9,998 |
| EXTEND | 0 | 0 | 0 | 0 | 10,055 |
| ZERO_FILL | 10,119 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,168 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 0 | 0 | 0 | 9,955 |
| RANDOM | 9,928 | 0 | 0 | 0 | 0 |

#### Anomalies

**00. ACCEPTED — `-`**

- Top frame: `-`
- Hits: 30,008
- First seen at input: 2
- Found via: LENGTH_EDGE of seed 2
- Minimized reproducer: 0 bytes (nominal 1184), saved under `results/corpus/jdk-ml-kem-768-pubkey-parse/`

### `jdk-ml-dsa-65-verify`

Of 100,000 inputs, 70,232 were exactly 3309 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 11 |
| REJECTED | 70,221 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,127 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,070 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 11 | 9,942 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,026 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,973 | 0 | 0 | 0 |
| EXTEND | 0 | 9,860 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,089 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,990 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,935 | 0 | 0 | 0 |
| RANDOM | 0 | 9,977 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-dsa-65-pubkey-parse`

Of 100,000 inputs, 69,925 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,925 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,994 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,977 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,186 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 9,874 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 0 | 0 | 0 | 10,083 |
| EXTEND | 0 | 0 | 0 | 0 | 9,957 |
| ZERO_FILL | 9,885 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,102 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 0 | 0 | 0 | 10,035 |
| RANDOM | 9,907 | 0 | 0 | 0 | 0 |

#### Anomalies

**00. ACCEPTED — `-`**

- Top frame: `-`
- Hits: 30,075
- First seen at input: 2
- Found via: LENGTH_EDGE of seed 2
- Minimized reproducer: 0 bytes (nominal 1952), saved under `results/corpus/jdk-ml-dsa-65-pubkey-parse/`

### `jdk-ml-kem-768-parse-encapsulate`

Of 100,000 inputs, 69,992 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,103 |
| REJECTED | 32,889 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,382 | 473 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,810 | 2,249 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,616 | 1,185 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,176 | 8,886 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,998 | 0 | 0 | 0 |
| EXTEND | 0 | 10,055 | 0 | 0 | 0 |
| ZERO_FILL | 10,119 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,168 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,955 | 0 | 0 | 0 |
| RANDOM | 0 | 9,928 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-dsa-65-parse-verify`

Of 100,000 inputs, 69,925 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 7 |
| REJECTED | 69,918 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,994 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,977 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 7 | 10,179 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,874 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,083 | 0 | 0 | 0 |
| EXTEND | 0 | 9,957 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,885 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,102 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,035 | 0 | 0 | 0 |
| RANDOM | 0 | 9,907 | 0 | 0 | 0 |

No anomalies.

