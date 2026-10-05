# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:24:41.910784Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 25.0.2 (Homebrew) |
| JDK PQC providers | ML-DSA: SUN, ML-KEM: SunJCE |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260719` |
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
| Wrong-length encoding accepted (decoder) | 59,832 |

## Summary

| Target | Kind | Nominal | Inputs | Inputs/s | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED | Distinct |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `jdk-ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 22,843 | 69,872 | 30,128 | 0 | 0 | 0 | 0 |
| `jdk-ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 20,743 | 70,237 | 0 | 0 | 0 | 29,763 | 1 |
| `jdk-ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 17,324 | 11 | 99,989 | 0 | 0 | 0 | 0 |
| `jdk-ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 21,209 | 69,931 | 0 | 0 | 0 | 30,069 | 1 |
| `jdk-ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 19,695 | 37,347 | 62,653 | 0 | 0 | 0 | 0 |
| `jdk-ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 13,499 | 12 | 99,988 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 200,000 inputs across 2 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 300,000 inputs across 3 decode target(s): 0 undocumented exception(s). Separately, 59,832 wrong-length encoding(s) were silently **accepted** — a decoder defect that H2 did not anticipate, since it fails without throwing. |
| **H3** | supported | 69,872 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 600,000 input(s) across 6 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `jdk-ml-kem-768-decap`

Of 100,000 inputs, 69,872 were exactly 1088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,872 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,059 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,917 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,915 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,084 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,125 | 0 | 0 | 0 |
| EXTEND | 0 | 10,106 | 0 | 0 | 0 |
| ZERO_FILL | 10,032 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,893 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,897 | 0 | 0 | 0 |
| RANDOM | 9,972 | 0 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-kem-768-pubkey-parse`

Of 100,000 inputs, 70,237 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,237 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,093 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,981 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,990 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,223 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 0 | 0 | 0 | 9,961 |
| EXTEND | 0 | 0 | 0 | 0 | 9,969 |
| ZERO_FILL | 10,157 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,846 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 0 | 0 | 0 | 9,833 |
| RANDOM | 9,947 | 0 | 0 | 0 | 0 |

#### Anomalies

**00. ACCEPTED — `-`**

- Top frame: `-`
- Hits: 29,763
- First seen at input: 9
- Found via: LENGTH_EDGE of seed 3
- Minimized reproducer: 0 bytes (nominal 1184), saved under `results/corpus/jdk-ml-kem-768-pubkey-parse/`

### `jdk-ml-dsa-65-verify`

Of 100,000 inputs, 70,325 were exactly 3309 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 11 |
| REJECTED | 70,314 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,022 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,067 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 11 | 9,979 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,117 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,971 | 0 | 0 | 0 |
| EXTEND | 0 | 9,782 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,996 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,919 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,922 | 0 | 0 | 0 |
| RANDOM | 0 | 10,214 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-dsa-65-pubkey-parse`

Of 100,000 inputs, 69,931 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,931 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,897 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,922 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,084 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 9,998 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 0 | 0 | 0 | 10,039 |
| EXTEND | 0 | 0 | 0 | 0 | 10,045 |
| ZERO_FILL | 10,021 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,991 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 0 | 0 | 0 | 9,985 |
| RANDOM | 10,018 | 0 | 0 | 0 | 0 |

#### Anomalies

**00. ACCEPTED — `-`**

- Top frame: `-`
- Hits: 30,069
- First seen at input: 6
- Found via: LENGTH_EDGE of seed 3
- Minimized reproducer: 0 bytes (nominal 1952), saved under `results/corpus/jdk-ml-dsa-65-pubkey-parse/`

### `jdk-ml-kem-768-parse-encapsulate`

Of 100,000 inputs, 70,237 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,347 |
| REJECTED | 32,890 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,522 | 571 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,761 | 2,220 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,787 | 1,203 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,120 | 9,103 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,961 | 0 | 0 | 0 |
| EXTEND | 0 | 9,969 | 0 | 0 | 0 |
| ZERO_FILL | 10,157 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,846 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,833 | 0 | 0 | 0 |
| RANDOM | 0 | 9,947 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-dsa-65-parse-verify`

Of 100,000 inputs, 69,931 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 12 |
| REJECTED | 69,919 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,897 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,922 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 12 | 10,072 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,998 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,039 | 0 | 0 | 0 |
| EXTEND | 0 | 10,045 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,021 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,991 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,985 | 0 | 0 | 0 |
| RANDOM | 0 | 10,018 | 0 | 0 | 0 |

No anomalies.

