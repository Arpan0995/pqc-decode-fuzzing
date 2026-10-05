# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:50:19.348218Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.86 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| JDK PQC providers | none (the jdk-* targets need JDK 24 or later) |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260723` |
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
| `ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 17,486 | 70,159 | 29,841 | 0 | 0 | 0 | 0 |
| `ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 28,812 | 37,125 | 62,875 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 15,217 | 14 | 99,986 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 27,536 | 69,823 | 30,177 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-verify` | VERIFY | 17088 | 100,000 | 946 | 8 | 99,992 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-pubkey-parse` | DECODE | 32 | 100,000 | 30,488 | 69,808 | 30,192 | 0 | 0 | 0 | 0 |
| `ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 22,717 | 37,125 | 62,875 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 11,307 | 8 | 99,992 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-parse-verify` | VERIFY | 32 | 100,000 | 967 | 4 | 99,996 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 400,000 inputs across 4 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 400,000 inputs across 4 decode target(s): 0 undocumented exception(s). |
| **H3** | supported | 70,159 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 900,000 input(s) across 9 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `ml-kem-768-decap`

Of 100,000 inputs, 70,159 were exactly 1088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,159 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,061 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,912 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,993 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,161 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,909 | 0 | 0 | 0 |
| EXTEND | 0 | 9,952 | 0 | 0 | 0 |
| ZERO_FILL | 9,947 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,008 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,980 | 0 | 0 | 0 |
| RANDOM | 10,077 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-pubkey-parse`

Of 100,000 inputs, 69,943 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,125 |
| REJECTED | 32,818 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,435 | 507 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,783 | 2,184 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,905 | 1,228 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,091 | 8,863 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,079 | 0 | 0 | 0 |
| EXTEND | 0 | 9,998 | 0 | 0 | 0 |
| ZERO_FILL | 9,911 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,969 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,980 | 0 | 0 | 0 |
| RANDOM | 0 | 10,067 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-verify`

Of 100,000 inputs, 70,017 were exactly 3309 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 14 |
| REJECTED | 70,003 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,034 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,113 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 14 | 10,055 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,869 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,896 | 0 | 0 | 0 |
| EXTEND | 0 | 10,027 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,862 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,116 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,060 | 0 | 0 | 0 |
| RANDOM | 0 | 9,954 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-pubkey-parse`

Of 100,000 inputs, 69,823 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,823 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,139 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,953 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,994 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,074 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,002 | 0 | 0 | 0 |
| EXTEND | 0 | 9,974 | 0 | 0 | 0 |
| ZERO_FILL | 9,840 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,848 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,201 | 0 | 0 | 0 |
| RANDOM | 9,975 | 0 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-verify`

Of 100,000 inputs, 69,978 were exactly 17088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 8 |
| REJECTED | 69,970 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,000 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,932 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8 | 9,931 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,955 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,998 | 0 | 0 | 0 |
| EXTEND | 0 | 10,056 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,104 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,989 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,968 | 0 | 0 | 0 |
| RANDOM | 0 | 10,059 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-pubkey-parse`

Of 100,000 inputs, 69,808 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,808 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,062 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,046 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,979 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,004 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,968 | 0 | 0 | 0 |
| EXTEND | 0 | 10,015 | 0 | 0 | 0 |
| ZERO_FILL | 9,912 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,883 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,209 | 0 | 0 | 0 |
| RANDOM | 9,922 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-parse-encapsulate`

Of 100,000 inputs, 69,943 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,125 |
| REJECTED | 32,818 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,435 | 507 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,783 | 2,184 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,905 | 1,228 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,091 | 8,863 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,079 | 0 | 0 | 0 |
| EXTEND | 0 | 9,998 | 0 | 0 | 0 |
| ZERO_FILL | 9,911 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,969 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,980 | 0 | 0 | 0 |
| RANDOM | 0 | 10,067 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-parse-verify`

Of 100,000 inputs, 69,823 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 8 |
| REJECTED | 69,815 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,139 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,953 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8 | 9,986 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,074 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,002 | 0 | 0 | 0 |
| EXTEND | 0 | 9,974 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,840 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,848 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,201 | 0 | 0 | 0 |
| RANDOM | 0 | 9,975 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-parse-verify`

Of 100,000 inputs, 69,808 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 4 |
| REJECTED | 69,804 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,062 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,046 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 4 | 9,975 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,004 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,968 | 0 | 0 | 0 |
| EXTEND | 0 | 10,015 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,912 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,883 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,209 | 0 | 0 | 0 |
| RANDOM | 0 | 9,922 | 0 | 0 | 0 |

No anomalies.

