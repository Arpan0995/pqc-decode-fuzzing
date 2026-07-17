# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-07-17T07:40:23.073877Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| Host | Mac OS X 27.0 aarch64, 10 cpus |
| Campaign seed | `20260717` |
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
| `ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 18,075 | 69,848 | 30,152 | 0 | 0 | 0 | 0 |
| `ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 34,598 | 37,312 | 62,688 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 16,409 | 10 | 99,990 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 34,281 | 70,174 | 29,826 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-verify` | VERIFY | 17088 | 100,000 | 948 | 13 | 99,987 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-pubkey-parse` | DECODE | 32 | 100,000 | 35,467 | 69,894 | 30,106 | 0 | 0 | 0 | 0 |
| `ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 26,099 | 37,312 | 62,688 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 12,304 | 9 | 99,991 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-parse-verify` | VERIFY | 32 | 100,000 | 942 | 7 | 99,993 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception (`IllegalArgumentException`, `RuntimeCryptoException`, `CryptoException`). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 400,000 inputs across 4 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 400,000 inputs across 4 decode target(s): 0 undocumented exception(s). |
| **H3** | supported | 69,848 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 900,000 input(s) across 9 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `ml-kem-768-decap`

Of 100,000 inputs, 69,848 were exactly 1088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,848 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,871 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,091 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,931 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,030 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,950 | 0 | 0 | 0 |
| EXTEND | 0 | 10,219 | 0 | 0 | 0 |
| ZERO_FILL | 9,972 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,947 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,983 | 0 | 0 | 0 |
| RANDOM | 10,006 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-pubkey-parse`

Of 100,000 inputs, 70,044 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,312 |
| REJECTED | 32,732 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,674 | 513 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,700 | 2,222 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,773 | 1,181 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,112 | 8,973 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,855 | 0 | 0 | 0 |
| EXTEND | 0 | 10,069 | 0 | 0 | 0 |
| ZERO_FILL | 10,053 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,745 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,032 | 0 | 0 | 0 |
| RANDOM | 0 | 10,098 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-verify`

Of 100,000 inputs, 69,985 were exactly 3309 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 10 |
| REJECTED | 69,975 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,888 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,205 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10 | 9,914 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,008 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,944 | 0 | 0 | 0 |
| EXTEND | 0 | 10,066 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,106 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,904 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,005 | 0 | 0 | 0 |
| RANDOM | 0 | 9,950 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-pubkey-parse`

Of 100,000 inputs, 70,174 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,174 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,909 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,163 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,089 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,109 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,982 | 0 | 0 | 0 |
| EXTEND | 0 | 9,955 | 0 | 0 | 0 |
| ZERO_FILL | 9,935 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,934 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,889 | 0 | 0 | 0 |
| RANDOM | 10,035 | 0 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-verify`

Of 100,000 inputs, 69,908 were exactly 17088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 13 |
| REJECTED | 69,895 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,927 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,856 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 13 | 9,971 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,947 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,955 | 0 | 0 | 0 |
| EXTEND | 0 | 10,094 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,012 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,080 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,043 | 0 | 0 | 0 |
| RANDOM | 0 | 10,102 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-pubkey-parse`

Of 100,000 inputs, 69,894 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,894 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,951 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,073 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,961 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 9,899 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,177 | 0 | 0 | 0 |
| EXTEND | 0 | 10,050 | 0 | 0 | 0 |
| ZERO_FILL | 10,010 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,956 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,879 | 0 | 0 | 0 |
| RANDOM | 10,044 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-parse-encapsulate`

Of 100,000 inputs, 70,044 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,312 |
| REJECTED | 32,732 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,674 | 513 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,700 | 2,222 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,773 | 1,181 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,112 | 8,973 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,855 | 0 | 0 | 0 |
| EXTEND | 0 | 10,069 | 0 | 0 | 0 |
| ZERO_FILL | 10,053 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,745 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,032 | 0 | 0 | 0 |
| RANDOM | 0 | 10,098 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-parse-verify`

Of 100,000 inputs, 70,174 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 9 |
| REJECTED | 70,165 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,909 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,163 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9 | 10,080 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,109 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,982 | 0 | 0 | 0 |
| EXTEND | 0 | 9,955 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,935 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,934 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,889 | 0 | 0 | 0 |
| RANDOM | 0 | 10,035 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-parse-verify`

Of 100,000 inputs, 69,894 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 7 |
| REJECTED | 69,887 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,951 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,073 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 7 | 9,954 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,899 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,177 | 0 | 0 | 0 |
| EXTEND | 0 | 10,050 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,010 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,956 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,879 | 0 | 0 | 0 |
| RANDOM | 0 | 10,044 | 0 | 0 | 0 |

No anomalies.

