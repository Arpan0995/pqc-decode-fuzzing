# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:46:13.852114Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.86 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| JDK PQC providers | none (the jdk-* targets need JDK 24 or later) |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260722` |
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
| `ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 16,725 | 69,897 | 30,103 | 0 | 0 | 0 | 0 |
| `ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 28,030 | 37,293 | 62,707 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 15,544 | 5 | 99,995 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 28,166 | 69,899 | 30,101 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-verify` | VERIFY | 17088 | 100,000 | 872 | 9 | 99,991 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-pubkey-parse` | DECODE | 32 | 100,000 | 31,167 | 69,965 | 30,035 | 0 | 0 | 0 | 0 |
| `ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 21,958 | 37,293 | 62,707 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 11,325 | 5 | 99,995 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-parse-verify` | VERIFY | 32 | 100,000 | 878 | 15 | 99,985 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 400,000 inputs across 4 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 400,000 inputs across 4 decode target(s): 0 undocumented exception(s). |
| **H3** | supported | 69,897 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 900,000 input(s) across 9 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `ml-kem-768-decap`

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

### `ml-kem-768-pubkey-parse`

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

### `ml-dsa-65-verify`

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
| TRUNCATE | 0 | 10,083 | 0 | 0 | 0 |
| EXTEND | 0 | 9,974 | 0 | 0 | 0 |
| ZERO_FILL | 10,087 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,921 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,044 | 0 | 0 | 0 |
| RANDOM | 9,881 | 0 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-verify`

Of 100,000 inputs, 69,877 were exactly 17088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 9 |
| REJECTED | 69,868 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,204 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,975 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9 | 9,979 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,870 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,914 | 0 | 0 | 0 |
| EXTEND | 0 | 10,110 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,745 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,006 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,099 | 0 | 0 | 0 |
| RANDOM | 0 | 10,089 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-pubkey-parse`

Of 100,000 inputs, 69,965 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,965 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,103 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,980 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,022 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,131 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,023 | 0 | 0 | 0 |
| EXTEND | 0 | 10,111 | 0 | 0 | 0 |
| ZERO_FILL | 10,113 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,845 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,901 | 0 | 0 | 0 |
| RANDOM | 9,771 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-parse-encapsulate`

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
| TRUNCATE | 0 | 10,083 | 0 | 0 | 0 |
| EXTEND | 0 | 9,974 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,087 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,921 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,044 | 0 | 0 | 0 |
| RANDOM | 0 | 9,881 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-parse-verify`

Of 100,000 inputs, 69,965 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 15 |
| REJECTED | 69,950 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,103 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 3 | 9,977 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 12 | 10,010 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,131 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,023 | 0 | 0 | 0 |
| EXTEND | 0 | 10,111 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,113 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,845 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,901 | 0 | 0 | 0 |
| RANDOM | 0 | 9,771 | 0 | 0 | 0 |

No anomalies.

