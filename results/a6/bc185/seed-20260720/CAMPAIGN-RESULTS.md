# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:34:57.225648Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| JDK PQC providers | none (the jdk-* targets need JDK 24 or later) |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260720` |
| Per-input timeout | 5000 ms |
| Full stack traces | yes (`-XX:-OmitStackTraceInFastThrow`) |

Every result is reproducible from the campaign seed: it fixes the key pairs, the seed corpus, and the mutation stream.

## Headline

900,000 inputs across 9 targets produced **0 distinct anomalies**.

| Defect class | Inputs |
|---|---:|
| Undocumented exception | 0 |
| Timeout (potential DoS) | 0 |
| Forgery accepted (verify path) | 0 |
| Wrong-length encoding accepted (decoder) | 0 |

No defects were found. This is an assurance result, not a proof of absence: it is bounded by the input budget above and by the blackbox mutation method (design §8). What makes it more than an untested claim is the BouncyCastle 1.84 control (design §13): the same harness finds a real defect there, so a null result here reflects the library rather than a harness that cannot see.

## Summary

| Target | Kind | Nominal | Inputs | Inputs/s | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED | Distinct |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 20,058 | 69,741 | 30,259 | 0 | 0 | 0 | 0 |
| `ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 36,482 | 37,133 | 62,867 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 18,217 | 8 | 99,992 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 37,056 | 69,967 | 30,033 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-verify` | VERIFY | 17088 | 100,000 | 785 | 11 | 99,989 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-pubkey-parse` | DECODE | 32 | 100,000 | 24,711 | 70,006 | 29,994 | 0 | 0 | 0 | 0 |
| `ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 18,374 | 37,133 | 62,867 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 8,339 | 17 | 99,983 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-parse-verify` | VERIFY | 32 | 100,000 | 773 | 12 | 99,988 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 400,000 inputs across 4 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 400,000 inputs across 4 decode target(s): 0 undocumented exception(s). |
| **H3** | supported | 69,741 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 900,000 input(s) across 9 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `ml-kem-768-decap`

Of 100,000 inputs, 69,741 were exactly 1088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,741 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,871 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,775 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,864 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 9,941 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,123 | 0 | 0 | 0 |
| EXTEND | 0 | 10,068 | 0 | 0 | 0 |
| ZERO_FILL | 10,060 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,003 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,068 | 0 | 0 | 0 |
| RANDOM | 10,227 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-pubkey-parse`

Of 100,000 inputs, 69,997 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,133 |
| REJECTED | 32,864 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,414 | 531 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,726 | 2,251 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,851 | 1,240 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,119 | 8,686 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,016 | 0 | 0 | 0 |
| EXTEND | 0 | 9,988 | 0 | 0 | 0 |
| ZERO_FILL | 10,023 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,151 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,999 | 0 | 0 | 0 |
| RANDOM | 0 | 10,005 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-verify`

Of 100,000 inputs, 70,018 were exactly 3309 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 8 |
| REJECTED | 70,010 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,795 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,092 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8 | 9,932 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,997 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,971 | 0 | 0 | 0 |
| EXTEND | 0 | 9,920 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,993 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,094 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,091 | 0 | 0 | 0 |
| RANDOM | 0 | 10,107 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-pubkey-parse`

Of 100,000 inputs, 69,967 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,967 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,003 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,005 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,109 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,008 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,931 | 0 | 0 | 0 |
| EXTEND | 0 | 10,135 | 0 | 0 | 0 |
| ZERO_FILL | 9,935 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,862 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,967 | 0 | 0 | 0 |
| RANDOM | 10,045 | 0 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-verify`

Of 100,000 inputs, 69,940 were exactly 17088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 11 |
| REJECTED | 69,929 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,942 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,868 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 11 | 10,013 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,983 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,863 | 0 | 0 | 0 |
| EXTEND | 0 | 10,117 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,898 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,172 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,080 | 0 | 0 | 0 |
| RANDOM | 0 | 10,053 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-pubkey-parse`

Of 100,000 inputs, 70,006 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,006 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,001 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,094 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,060 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,020 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,031 | 0 | 0 | 0 |
| EXTEND | 0 | 10,060 | 0 | 0 | 0 |
| ZERO_FILL | 9,915 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,962 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,903 | 0 | 0 | 0 |
| RANDOM | 9,954 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-parse-encapsulate`

Of 100,000 inputs, 69,997 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,133 |
| REJECTED | 32,864 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,414 | 531 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,726 | 2,251 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,851 | 1,240 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,119 | 8,686 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,016 | 0 | 0 | 0 |
| EXTEND | 0 | 9,988 | 0 | 0 | 0 |
| ZERO_FILL | 10,023 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,151 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,999 | 0 | 0 | 0 |
| RANDOM | 0 | 10,005 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-parse-verify`

Of 100,000 inputs, 69,967 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 17 |
| REJECTED | 69,950 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,003 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,005 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 17 | 10,092 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,008 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,931 | 0 | 0 | 0 |
| EXTEND | 0 | 10,135 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,935 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,862 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,967 | 0 | 0 | 0 |
| RANDOM | 0 | 10,045 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-parse-verify`

Of 100,000 inputs, 70,006 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 12 |
| REJECTED | 69,994 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,001 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 1 | 10,093 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 11 | 10,049 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,020 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,031 | 0 | 0 | 0 |
| EXTEND | 0 | 10,060 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,915 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,962 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,903 | 0 | 0 | 0 |
| RANDOM | 0 | 9,954 | 0 | 0 | 0 |

No anomalies.

