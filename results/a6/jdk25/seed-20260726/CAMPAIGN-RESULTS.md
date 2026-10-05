# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:28:11.179896Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 25.0.2 (Homebrew) |
| JDK PQC providers | ML-DSA: SUN, ML-KEM: SunJCE |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260726` |
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
| Wrong-length encoding accepted (decoder) | 59,728 |

## Summary

| Target | Kind | Nominal | Inputs | Inputs/s | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED | Distinct |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `jdk-ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 22,148 | 70,103 | 29,897 | 0 | 0 | 0 | 0 |
| `jdk-ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 20,732 | 70,245 | 0 | 0 | 0 | 29,755 | 1 |
| `jdk-ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 18,022 | 5 | 99,995 | 0 | 0 | 0 | 0 |
| `jdk-ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 22,289 | 70,027 | 0 | 0 | 0 | 29,973 | 1 |
| `jdk-ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 19,669 | 37,172 | 62,828 | 0 | 0 | 0 | 0 |
| `jdk-ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 13,832 | 11 | 99,989 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 200,000 inputs across 2 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 300,000 inputs across 3 decode target(s): 0 undocumented exception(s). Separately, 59,728 wrong-length encoding(s) were silently **accepted** — a decoder defect that H2 did not anticipate, since it fails without throwing. |
| **H3** | supported | 70,103 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 600,000 input(s) across 6 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `jdk-ml-kem-768-decap`

Of 100,000 inputs, 70,103 were exactly 1088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,103 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,154 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,957 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,886 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,036 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,003 | 0 | 0 | 0 |
| EXTEND | 0 | 9,968 | 0 | 0 | 0 |
| ZERO_FILL | 10,078 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,965 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,926 | 0 | 0 | 0 |
| RANDOM | 10,027 | 0 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-kem-768-pubkey-parse`

Of 100,000 inputs, 70,245 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,245 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,010 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,054 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,070 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,056 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 0 | 0 | 0 | 9,951 |
| EXTEND | 0 | 0 | 0 | 0 | 9,931 |
| ZERO_FILL | 9,971 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,107 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 0 | 0 | 0 | 9,873 |
| RANDOM | 9,977 | 0 | 0 | 0 | 0 |

#### Anomalies

**00. ACCEPTED — `-`**

- Top frame: `-`
- Hits: 29,755
- First seen at input: 13
- Found via: LENGTH_EDGE of seed 1
- Minimized reproducer: 0 bytes (nominal 1184), saved under `results/corpus/jdk-ml-kem-768-pubkey-parse/`

### `jdk-ml-dsa-65-verify`

Of 100,000 inputs, 70,392 were exactly 3309 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 5 |
| REJECTED | 70,387 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,072 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,035 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 5 | 9,870 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,182 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,770 | 0 | 0 | 0 |
| EXTEND | 0 | 9,918 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,173 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,864 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,920 | 0 | 0 | 0 |
| RANDOM | 0 | 10,191 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-dsa-65-pubkey-parse`

Of 100,000 inputs, 70,027 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,027 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,976 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,034 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,256 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 9,871 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 0 | 0 | 0 | 9,820 |
| EXTEND | 0 | 0 | 0 | 0 | 10,022 |
| ZERO_FILL | 9,909 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,000 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 0 | 0 | 0 | 10,131 |
| RANDOM | 9,981 | 0 | 0 | 0 | 0 |

#### Anomalies

**00. ACCEPTED — `-`**

- Top frame: `-`
- Hits: 29,973
- First seen at input: 18
- Found via: LENGTH_EDGE of seed 3
- Minimized reproducer: 0 bytes (nominal 1952), saved under `results/corpus/jdk-ml-dsa-65-pubkey-parse/`

### `jdk-ml-kem-768-parse-encapsulate`

Of 100,000 inputs, 70,245 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,172 |
| REJECTED | 33,073 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,462 | 548 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,753 | 2,301 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,888 | 1,182 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,098 | 8,958 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,951 | 0 | 0 | 0 |
| EXTEND | 0 | 9,931 | 0 | 0 | 0 |
| ZERO_FILL | 9,971 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,107 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,873 | 0 | 0 | 0 |
| RANDOM | 0 | 9,977 | 0 | 0 | 0 |

No anomalies.

### `jdk-ml-dsa-65-parse-verify`

Of 100,000 inputs, 70,027 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 11 |
| REJECTED | 70,016 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,976 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,034 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 11 | 10,245 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,871 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,820 | 0 | 0 | 0 |
| EXTEND | 0 | 10,022 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,909 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,000 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,131 | 0 | 0 | 0 |
| RANDOM | 0 | 9,981 | 0 | 0 | 0 |

No anomalies.

