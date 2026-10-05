# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:22:17.577631Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.84 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| JDK PQC providers | none (the jdk-* targets need JDK 24 or later) |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260722` |
| Per-input timeout | 5000 ms |
| Full stack traces | yes (`-XX:-OmitStackTraceInFastThrow`) |

Every result is reproducible from the campaign seed: it fixes the key pairs, the seed corpus, and the mutation stream.

## Headline

200,000 inputs across 2 targets produced **2 distinct anomalies**.

| Defect class | Inputs |
|---|---:|
| Undocumented exception | 8,236 |
| Timeout (potential DoS) | 0 |
| Forgery accepted (verify path) | 0 |
| Wrong-length encoding accepted (decoder) | 26,577 |

## Summary

| Target | Kind | Nominal | Inputs | Inputs/s | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED | Distinct |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 34,092 | 69,899 | 3,524 | 0 | 0 | 26,577 | 1 |
| `ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 8,505 | 5 | 91,759 | 8,236 | 0 | 0 | 1 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | not supported | 100,000 inputs across 1 verify target(s): 8,236 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 100,000 inputs across 1 decode target(s): 0 undocumented exception(s). Separately, 26,577 wrong-length encoding(s) were silently **accepted** — a decoder defect that H2 did not anticipate, since it fails without throwing. |
| **H3** | not supported | No decapsulation target ran. |
| **H4** | supported | 200,000 input(s) across 2 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `ml-dsa-65-pubkey-parse`

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
| TRUNCATE | 0 | 154 | 0 | 0 | 9,929 |
| EXTEND | 0 | 0 | 0 | 0 | 9,974 |
| ZERO_FILL | 10,087 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,921 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 3,370 | 0 | 0 | 6,674 |
| RANDOM | 9,881 | 0 | 0 | 0 | 0 |

#### Anomalies

**00. ACCEPTED — `-`**

- Top frame: `-`
- Hits: 26,577
- First seen at input: 2
- Found via: TRUNCATE of seed 0
- Minimized reproducer: 33 bytes (nominal 1952), saved under `results/corpus/ml-dsa-65-pubkey-parse/`

### `ml-dsa-65-parse-verify`

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
| TRUNCATE | 0 | 1,847 | 8,236 | 0 | 0 |
| EXTEND | 0 | 9,974 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,087 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,921 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,044 | 0 | 0 | 0 |
| RANDOM | 0 | 9,881 | 0 | 0 | 0 |

#### Anomalies

**00. UNEXPECTED_EXCEPTION — `java.lang.ArrayIndexOutOfBoundsException`**

- Top frame: `org.bouncycastle.crypto.signers.mldsa.Packing.unpackPublicKey`
- Message: `arraycopy: length -216 is negative`
- Hits: 8,236
- First seen at input: 6
- Found via: TRUNCATE of seed 0
- Minimized reproducer: 33 bytes (nominal 1952), saved under `results/corpus/ml-dsa-65-parse-verify/`

