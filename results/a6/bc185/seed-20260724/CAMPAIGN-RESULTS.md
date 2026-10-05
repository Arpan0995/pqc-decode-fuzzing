# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:55:00.037489Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| JDK PQC providers | none (the jdk-* targets need JDK 24 or later) |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260724` |
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
| `ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 20,892 | 70,353 | 29,647 | 0 | 0 | 0 | 0 |
| `ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 37,077 | 37,137 | 62,863 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 17,786 | 10 | 99,990 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 37,149 | 69,956 | 30,044 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-verify` | VERIFY | 17088 | 100,000 | 740 | 16 | 99,984 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-pubkey-parse` | DECODE | 32 | 100,000 | 37,108 | 69,875 | 30,125 | 0 | 0 | 0 | 0 |
| `ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 27,725 | 37,137 | 62,863 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 12,609 | 11 | 99,989 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-parse-verify` | VERIFY | 32 | 100,000 | 746 | 18 | 99,982 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 400,000 inputs across 4 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 400,000 inputs across 4 decode target(s): 0 undocumented exception(s). |
| **H3** | supported | 70,353 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 900,000 input(s) across 9 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `ml-kem-768-decap`

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

### `ml-kem-768-pubkey-parse`

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

### `ml-dsa-65-verify`

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

### `ml-dsa-65-pubkey-parse`

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
| TRUNCATE | 0 | 9,907 | 0 | 0 | 0 |
| EXTEND | 0 | 10,027 | 0 | 0 | 0 |
| ZERO_FILL | 10,000 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,026 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,110 | 0 | 0 | 0 |
| RANDOM | 10,078 | 0 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-verify`

Of 100,000 inputs, 70,148 were exactly 17088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 16 |
| REJECTED | 70,132 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,023 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,864 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 16 | 10,054 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,062 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,969 | 0 | 0 | 0 |
| EXTEND | 0 | 10,023 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,006 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,981 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,860 | 0 | 0 | 0 |
| RANDOM | 0 | 10,142 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-pubkey-parse`

Of 100,000 inputs, 69,875 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 69,875 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 10,068 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,000 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,997 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 9,933 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,160 | 0 | 0 | 0 |
| EXTEND | 0 | 9,858 | 0 | 0 | 0 |
| ZERO_FILL | 9,958 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,037 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,107 | 0 | 0 | 0 |
| RANDOM | 9,882 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-parse-encapsulate`

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

### `ml-dsa-65-parse-verify`

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

### `slh-dsa-sha2-128f-parse-verify`

Of 100,000 inputs, 69,875 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 18 |
| REJECTED | 69,857 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,068 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 4 | 9,996 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 14 | 9,983 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,933 | 0 | 0 | 0 |
| TRUNCATE | 0 | 10,160 | 0 | 0 | 0 |
| EXTEND | 0 | 9,858 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,958 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,037 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,107 | 0 | 0 | 0 |
| RANDOM | 0 | 9,882 | 0 | 0 | 0 |

No anomalies.

