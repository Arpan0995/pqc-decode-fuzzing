# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T19:04:35.620060Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| JDK PQC providers | none (the jdk-* targets need JDK 24 or later) |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260726` |
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
| `ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 19,777 | 70,103 | 29,897 | 0 | 0 | 0 | 0 |
| `ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 32,148 | 37,172 | 62,828 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 16,068 | 5 | 99,995 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 31,020 | 70,027 | 29,973 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-verify` | VERIFY | 17088 | 100,000 | 852 | 9 | 99,991 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-pubkey-parse` | DECODE | 32 | 100,000 | 28,956 | 69,810 | 30,190 | 0 | 0 | 0 | 0 |
| `ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 21,689 | 37,172 | 62,828 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 11,719 | 11 | 99,989 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-parse-verify` | VERIFY | 32 | 100,000 | 833 | 20 | 99,980 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 400,000 inputs across 4 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 400,000 inputs across 4 decode target(s): 0 undocumented exception(s). |
| **H3** | supported | 70,103 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 900,000 input(s) across 9 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `ml-kem-768-decap`

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

### `ml-kem-768-pubkey-parse`

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

### `ml-dsa-65-verify`

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

### `ml-dsa-65-pubkey-parse`

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
| TRUNCATE | 0 | 9,820 | 0 | 0 | 0 |
| EXTEND | 0 | 10,022 | 0 | 0 | 0 |
| ZERO_FILL | 9,909 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,000 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,131 | 0 | 0 | 0 |
| RANDOM | 9,981 | 0 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-verify`

Of 100,000 inputs, 69,937 were exactly 17088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 9 |
| REJECTED | 69,928 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,939 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,153 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9 | 9,964 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,122 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,058 | 0 | 0 | 0 |
| EXTEND | 0 | 10,029 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,830 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,924 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,976 | 0 | 0 | 0 |
| RANDOM | 0 | 9,996 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-pubkey-parse`

Of 100,000 inputs, 69,810 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,810 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,947 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,009 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,832 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,197 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,868 | 0 | 0 | 0 |
| EXTEND | 0 | 10,121 | 0 | 0 | 0 |
| ZERO_FILL | 9,954 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,895 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,201 | 0 | 0 | 0 |
| RANDOM | 9,976 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-parse-encapsulate`

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

### `ml-dsa-65-parse-verify`

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

### `slh-dsa-sha2-128f-parse-verify`

Of 100,000 inputs, 69,810 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 20 |
| REJECTED | 69,790 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,947 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 3 | 10,006 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 17 | 9,815 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,197 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,868 | 0 | 0 | 0 |
| EXTEND | 0 | 10,121 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,954 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,895 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,201 | 0 | 0 | 0 |
| RANDOM | 0 | 9,976 | 0 | 0 | 0 |

No anomalies.

