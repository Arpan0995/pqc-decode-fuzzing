# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T19:00:03.390258Z by `FuzzCampaign`.

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
| `ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 20,729 | 70,167 | 29,833 | 0 | 0 | 0 | 0 |
| `ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 38,594 | 37,103 | 62,897 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 18,233 | 11 | 99,989 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 37,190 | 69,925 | 30,075 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-verify` | VERIFY | 17088 | 100,000 | 747 | 14 | 99,986 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-pubkey-parse` | DECODE | 32 | 100,000 | 39,094 | 70,011 | 29,989 | 0 | 0 | 0 | 0 |
| `ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 28,754 | 37,103 | 62,897 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 12,915 | 7 | 99,993 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-parse-verify` | VERIFY | 32 | 100,000 | 716 | 12 | 99,988 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 400,000 inputs across 4 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 400,000 inputs across 4 decode target(s): 0 undocumented exception(s). |
| **H3** | supported | 70,167 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 900,000 input(s) across 9 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `ml-kem-768-decap`

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

### `ml-kem-768-pubkey-parse`

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

### `ml-dsa-65-verify`

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

### `ml-dsa-65-pubkey-parse`

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
| TRUNCATE | 0 | 10,083 | 0 | 0 | 0 |
| EXTEND | 0 | 9,957 | 0 | 0 | 0 |
| ZERO_FILL | 9,885 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,102 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,035 | 0 | 0 | 0 |
| RANDOM | 9,907 | 0 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-verify`

Of 100,000 inputs, 69,742 were exactly 17088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 14 |
| REJECTED | 69,728 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,038 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,025 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 14 | 9,898 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,072 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,066 | 0 | 0 | 0 |
| EXTEND | 0 | 9,960 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,978 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,074 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,232 | 0 | 0 | 0 |
| RANDOM | 0 | 9,643 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-pubkey-parse`

Of 100,000 inputs, 70,011 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,011 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,982 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,139 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,018 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 9,992 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,006 | 0 | 0 | 0 |
| EXTEND | 0 | 9,992 | 0 | 0 | 0 |
| ZERO_FILL | 9,864 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,015 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,991 | 0 | 0 | 0 |
| RANDOM | 10,001 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-parse-encapsulate`

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

### `ml-dsa-65-parse-verify`

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

### `slh-dsa-sha2-128f-parse-verify`

Of 100,000 inputs, 70,011 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 12 |
| REJECTED | 69,999 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,982 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,139 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 11 | 10,007 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1 | 9,991 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,006 | 0 | 0 | 0 |
| EXTEND | 0 | 9,992 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,864 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,015 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,991 | 0 | 0 | 0 |
| RANDOM | 0 | 10,001 | 0 | 0 | 0 |

No anomalies.

