# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:26:11.757733Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 25.0.2 (Homebrew) |
| JDK PQC providers | ML-DSA: SUN, ML-KEM: SunJCE |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260722` |
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
| Wrong-length encoding accepted (decoder) | 60,323 |

## Summary

| Target | Kind | Nominal | Inputs | Inputs/s | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED | Distinct |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `jdk-ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 24,896 | 69,897 | 30,103 | 0 | 0 | 0 | 0 |
| `jdk-ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 24,190 | 69,778 | 0 | 0 | 0 | 30,222 | 1 |
| `jdk-ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 19,907 | 5 | 99,995 | 0 | 0 | 0 | 0 |
| `jdk-ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 24,412 | 69,899 | 0 | 0 | 0 | 30,101 | 1 |
| `jdk-ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 21,691 | 37,293 | 62,707 | 0 | 0 | 0 | 0 |
| `jdk-ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 14,707 | 5 | 99,995 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 200,000 inputs across 2 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 300,000 inputs across 3 decode target(s): 0 undocumented exception(s). Separately, 60,323 wrong-length encoding(s) were silently **accepted** — a decoder defect that H2 did not anticipate, since it fails without throwing. |
| **H3** | supported | 69,897 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 600,000 input(s) across 6 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `jdk-ml-kem-768-decap`

Of 100,000 inputs, 69,897 were exactly 1088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,897 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,960 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,934 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,910 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,036 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,984 | 0 | 0 | 0 |
| EXTEND | 0 | 10,097 | 0 | 0 | 0 |
| ZERO_FILL | 10,110 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,982 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,022 | 0 | 0 | 0 |
| RANDOM | 9,965 | 0 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-kem-768-pubkey-parse`

Of 100,000 inputs, 69,778 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,778 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,086 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,962 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,931 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 9,970 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 0 | 0 | 0 | 10,052 |
| EXTEND | 0 | 0 | 0 | 0 | 10,078 |
| ZERO_FILL | 10,021 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,973 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 0 | 0 | 0 | 10,092 |
| RANDOM | 9,835 | 0 | 0 | 0 | 0 |

#### Anomalies

**00. ACCEPTED — `-`**

- Top frame: `-`
- Hits: 30,222
- First seen at input: 2
- Found via: LENGTH_EDGE of seed 1
- Minimized reproducer: 0 bytes (nominal 1184), saved under `results/corpus/jdk-ml-kem-768-pubkey-parse/`

### `jdk-ml-dsa-65-verify`

Of 100,000 inputs, 69,847 were exactly 3309 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 5 |
| REJECTED | 69,842 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,024 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,044 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 5 | 9,893 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,894 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,190 | 0 | 0 | 0 |
| EXTEND | 0 | 10,098 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,914 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,126 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,865 | 0 | 0 | 0 |
| RANDOM | 0 | 9,947 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-dsa-65-pubkey-parse`

Of 100,000 inputs, 69,899 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,899 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,045 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,972 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,904 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,089 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 0 | 0 | 0 | 10,083 |
| EXTEND | 0 | 0 | 0 | 0 | 9,974 |
| ZERO_FILL | 10,087 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,921 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 0 | 0 | 0 | 10,044 |
| RANDOM | 9,881 | 0 | 0 | 0 | 0 |

#### Anomalies

**00. ACCEPTED — `-`**

- Top frame: `-`
- Hits: 30,101
- First seen at input: 2
- Found via: LENGTH_EDGE of seed 0
- Minimized reproducer: 0 bytes (nominal 1952), saved under `results/corpus/jdk-ml-dsa-65-pubkey-parse/`

### `jdk-ml-kem-768-parse-encapsulate`

Of 100,000 inputs, 69,778 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,293 |
| REJECTED | 32,485 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,607 | 479 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,796 | 2,166 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,715 | 1,216 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,154 | 8,816 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,052 | 0 | 0 | 0 |
| EXTEND | 0 | 10,078 | 0 | 0 | 0 |
| ZERO_FILL | 10,021 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,973 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,092 | 0 | 0 | 0 |
| RANDOM | 0 | 9,835 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-dsa-65-parse-verify`

Of 100,000 inputs, 69,899 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 5 |
| REJECTED | 69,894 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,045 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,972 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 5 | 9,899 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,089 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,083 | 0 | 0 | 0 |
| EXTEND | 0 | 9,974 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,087 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,921 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,044 | 0 | 0 | 0 |
| RANDOM | 0 | 9,881 | 0 | 0 | 0 |

No anomalies.

