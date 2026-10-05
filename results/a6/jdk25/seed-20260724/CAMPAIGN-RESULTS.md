# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:27:07.781700Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 25.0.2 (Homebrew) |
| JDK PQC providers | ML-DSA: SUN, ML-KEM: SunJCE |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260724` |
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
| Wrong-length encoding accepted (decoder) | 60,306 |

## Summary

| Target | Kind | Nominal | Inputs | Inputs/s | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED | Distinct |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `jdk-ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 26,800 | 70,353 | 29,647 | 0 | 0 | 0 | 0 |
| `jdk-ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 25,429 | 69,738 | 0 | 0 | 0 | 30,262 | 1 |
| `jdk-ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 20,291 | 10 | 99,990 | 0 | 0 | 0 | 0 |
| `jdk-ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 25,002 | 69,956 | 0 | 0 | 0 | 30,044 | 1 |
| `jdk-ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 22,631 | 37,137 | 62,863 | 0 | 0 | 0 | 0 |
| `jdk-ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 14,476 | 11 | 99,989 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 200,000 inputs across 2 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 300,000 inputs across 3 decode target(s): 0 undocumented exception(s). Separately, 60,306 wrong-length encoding(s) were silently **accepted** — a decoder defect that H2 did not anticipate, since it fails without throwing. |
| **H3** | supported | 70,353 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 600,000 input(s) across 6 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `jdk-ml-kem-768-decap`

Of 100,000 inputs, 70,353 were exactly 1088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,353 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,059 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,976 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,074 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,117 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,876 | 0 | 0 | 0 |
| EXTEND | 0 | 9,909 | 0 | 0 | 0 |
| ZERO_FILL | 10,177 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,847 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,862 | 0 | 0 | 0 |
| RANDOM | 10,103 | 0 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-kem-768-pubkey-parse`

Of 100,000 inputs, 69,738 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,738 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,916 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,996 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,958 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,007 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 0 | 0 | 0 | 10,055 |
| EXTEND | 0 | 0 | 0 | 0 | 10,219 |
| ZERO_FILL | 10,145 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,788 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 0 | 0 | 0 | 9,988 |
| RANDOM | 9,928 | 0 | 0 | 0 | 0 |

#### Anomalies

**00. ACCEPTED — `-`**

- Top frame: `-`
- Hits: 30,262
- First seen at input: 1
- Found via: LENGTH_EDGE of seed 3
- Minimized reproducer: 0 bytes (nominal 1184), saved under `results/corpus/jdk-ml-kem-768-pubkey-parse/`

### `jdk-ml-dsa-65-verify`

Of 100,000 inputs, 69,717 were exactly 3309 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 10 |
| REJECTED | 69,707 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,035 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,980 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10 | 10,148 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,928 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,078 | 0 | 0 | 0 |
| EXTEND | 0 | 10,077 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,799 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,911 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,128 | 0 | 0 | 0 |
| RANDOM | 0 | 9,906 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-dsa-65-pubkey-parse`

Of 100,000 inputs, 69,956 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,956 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,031 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,801 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,003 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,017 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 0 | 0 | 0 | 9,907 |
| EXTEND | 0 | 0 | 0 | 0 | 10,027 |
| ZERO_FILL | 10,000 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,026 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 0 | 0 | 0 | 10,110 |
| RANDOM | 10,078 | 0 | 0 | 0 | 0 |

#### Anomalies

**00. ACCEPTED — `-`**

- Top frame: `-`
- Hits: 30,044
- First seen at input: 1
- Found via: LENGTH_EDGE of seed 3
- Minimized reproducer: 0 bytes (nominal 1952), saved under `results/corpus/jdk-ml-dsa-65-pubkey-parse/`

### `jdk-ml-kem-768-parse-encapsulate`

Of 100,000 inputs, 69,738 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,137 |
| REJECTED | 32,601 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,398 | 518 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,748 | 2,248 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,706 | 1,252 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,140 | 8,867 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,055 | 0 | 0 | 0 |
| EXTEND | 0 | 10,219 | 0 | 0 | 0 |
| ZERO_FILL | 10,145 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,788 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,988 | 0 | 0 | 0 |
| RANDOM | 0 | 9,928 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-dsa-65-parse-verify`

Of 100,000 inputs, 69,956 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 11 |
| REJECTED | 69,945 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,031 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,801 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10 | 9,993 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1 | 10,016 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,907 | 0 | 0 | 0 |
| EXTEND | 0 | 10,027 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,000 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,026 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,110 | 0 | 0 | 0 |
| RANDOM | 0 | 10,078 | 0 | 0 | 0 |

No anomalies.

