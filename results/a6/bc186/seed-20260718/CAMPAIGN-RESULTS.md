# Campaign Results — Fuzzing Java PQC Decode and Verify Paths

Generated 2026-09-21T18:29:25.551391Z by `FuzzCampaign`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.86 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| JDK PQC providers | none (the jdk-* targets need JDK 24 or later) |
| Host | Mac OS X 27.2 aarch64, 10 cpus |
| Campaign seed | `20260718` |
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
| `ml-kem-768-decap` | DECAPSULATE | 1088 | 100,000 | 19,537 | 70,038 | 29,962 | 0 | 0 | 0 | 0 |
| `ml-kem-768-pubkey-parse` | DECODE | 1184 | 100,000 | 34,600 | 37,229 | 62,771 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-verify` | VERIFY | 3309 | 100,000 | 15,748 | 7 | 99,993 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-pubkey-parse` | DECODE | 1952 | 100,000 | 37,710 | 70,293 | 29,707 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-verify` | VERIFY | 17088 | 100,000 | 892 | 10 | 99,990 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-pubkey-parse` | DECODE | 32 | 100,000 | 37,129 | 70,038 | 29,962 | 0 | 0 | 0 | 0 |
| `ml-kem-768-parse-encapsulate` | DECODE | 1184 | 100,000 | 25,643 | 37,229 | 62,771 | 0 | 0 | 0 | 0 |
| `ml-dsa-65-parse-verify` | VERIFY | 1952 | 100,000 | 10,783 | 5 | 99,995 | 0 | 0 | 0 | 0 |
| `slh-dsa-sha2-128f-parse-verify` | VERIFY | 32 | 100,000 | 894 | 15 | 99,985 | 0 | 0 | 0 | 0 |

Outcomes are as pre-registered (design §6). `REJECTED` is the *correct* response to malformed input — verification returning false, or a documented exception under the rule for the provider driven: for BouncyCastle `IllegalArgumentException`, `RuntimeCryptoException` or `CryptoException`; for the JDK targets `InvalidKeySpecException`, `InvalidKeyException`, `SignatureException` or `DecapsulateException` (design A5). `UNEXPECTED_EXCEPTION` is anything else thrown, and is the primary defect class. Throughput is exploratory and host-specific; it also carries the cost of running every input under a timeout watchdog.

## Pre-registered hypotheses

Fixed in the design before any data was collected (§4), and scored here mechanically from the counts above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | 400,000 inputs across 4 verify target(s): 0 undocumented exception(s), 0 forgery acceptance(s). |
| **H2** | not supported | 400,000 inputs across 4 decode target(s): 0 undocumented exception(s). |
| **H3** | supported | 70,038 correct-length ciphertext(s) decapsulated: 0 threw. (Wrong-length inputs are outside this hypothesis and are reported separately.) |
| **H4** | supported | 900,000 input(s) across 9 target(s): 0 timeout(s). |

- **H1** — The ML-DSA and SLH-DSA verify paths are total: no malformed signature causes an uncaught exception or a forgery acceptance.
- **H2** — The public-key decoders mostly reject with documented exceptions, but fuzzing surfaces at least one input triggering an undocumented runtime exception.
- **H3** — ML-KEM decapsulation never throws for a correct-length ciphertext: the Fujisaki-Okamoto implicit-rejection branch always returns a secret.
- **H4** — No input causes a hang (non-termination or super-linear blow-up) within the per-input time budget.

Note that **H2 predicts defects**, so for H2 alone "supported" is the finding and "not supported" is the assurance result.

## Per target

### `ml-kem-768-decap`

Of 100,000 inputs, 70,038 were exactly 1088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,038 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,935 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,045 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,964 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,108 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,927 | 0 | 0 | 0 |
| EXTEND | 0 | 9,990 | 0 | 0 | 0 |
| ZERO_FILL | 10,023 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,979 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,045 | 0 | 0 | 0 |
| RANDOM | 9,984 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-pubkey-parse`

Of 100,000 inputs, 70,087 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,229 |
| REJECTED | 32,858 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,495 | 490 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,626 | 2,195 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,776 | 1,168 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,157 | 8,988 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,832 | 0 | 0 | 0 |
| EXTEND | 0 | 9,953 | 0 | 0 | 0 |
| ZERO_FILL | 10,175 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,074 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,128 | 0 | 0 | 0 |
| RANDOM | 0 | 9,943 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-verify`

Of 100,000 inputs, 70,050 were exactly 3309 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 7 |
| REJECTED | 70,043 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 10,128 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,947 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 7 | 9,967 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,952 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,887 | 0 | 0 | 0 |
| EXTEND | 0 | 9,882 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 9,819 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,115 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,181 | 0 | 0 | 0 |
| RANDOM | 0 | 10,115 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-pubkey-parse`

Of 100,000 inputs, 70,293 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,293 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,923 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 10,105 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10,046 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 10,053 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,966 | 0 | 0 | 0 |
| EXTEND | 0 | 9,966 | 0 | 0 | 0 |
| ZERO_FILL | 10,063 | 0 | 0 | 0 | 0 |
| ONES_FILL | 10,030 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,775 | 0 | 0 | 0 |
| RANDOM | 10,073 | 0 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-verify`

Of 100,000 inputs, 70,107 were exactly 17088 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 10 |
| REJECTED | 70,097 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,971 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 9,999 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 10 | 9,893 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 9,947 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,807 | 0 | 0 | 0 |
| EXTEND | 0 | 9,980 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,050 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,977 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,106 | 0 | 0 | 0 |
| RANDOM | 0 | 10,260 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-pubkey-parse`

Of 100,000 inputs, 70,038 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 70,038 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,945 | 0 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 9,960 | 0 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 9,900 | 0 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 9,991 | 0 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,918 | 0 | 0 | 0 |
| EXTEND | 0 | 9,946 | 0 | 0 | 0 |
| ZERO_FILL | 10,107 | 0 | 0 | 0 | 0 |
| ONES_FILL | 9,975 | 0 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,098 | 0 | 0 | 0 |
| RANDOM | 10,160 | 0 | 0 | 0 | 0 |

No anomalies.

### `ml-kem-768-parse-encapsulate`

Of 100,000 inputs, 70,087 were exactly 1184 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 37,229 |
| REJECTED | 32,858 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 9,495 | 490 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 7,626 | 2,195 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 8,776 | 1,168 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1,157 | 8,988 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,832 | 0 | 0 | 0 |
| EXTEND | 0 | 9,953 | 0 | 0 | 0 |
| ZERO_FILL | 10,175 | 0 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,074 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,128 | 0 | 0 | 0 |
| RANDOM | 0 | 9,943 | 0 | 0 | 0 |

No anomalies.

### `ml-dsa-65-parse-verify`

Of 100,000 inputs, 70,293 were exactly 1952 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 5 |
| REJECTED | 70,288 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,923 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 0 | 10,105 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 5 | 10,041 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 0 | 10,053 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,966 | 0 | 0 | 0 |
| EXTEND | 0 | 9,966 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,063 | 0 | 0 | 0 |
| ONES_FILL | 0 | 10,030 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 9,775 | 0 | 0 | 0 |
| RANDOM | 0 | 10,073 | 0 | 0 | 0 |

No anomalies.

### `slh-dsa-sha2-128f-parse-verify`

Of 100,000 inputs, 70,038 were exactly 32 bytes — the correct length, so they passed any length check and reached the real parsing.

| Correct-length outcome | Count |
|---|---:|
| OK | 15 |
| REJECTED | 70,023 |

| Mutation | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED |
|---|---:|---:|---:|---:|---:|
| BIT_FLIP | 0 | 9,945 | 0 | 0 | 0 |
| MULTI_BIT_FLIP | 2 | 9,958 | 0 | 0 | 0 |
| BYTE_SUBSTITUTE | 12 | 9,888 | 0 | 0 | 0 |
| CHUNK_RANDOMIZE | 1 | 9,990 | 0 | 0 | 0 |
| TRUNCATE | 0 | 9,918 | 0 | 0 | 0 |
| EXTEND | 0 | 9,946 | 0 | 0 | 0 |
| ZERO_FILL | 0 | 10,107 | 0 | 0 | 0 |
| ONES_FILL | 0 | 9,975 | 0 | 0 | 0 |
| LENGTH_EDGE | 0 | 10,098 | 0 | 0 | 0 |
| RANDOM | 0 | 10,160 | 0 | 0 | 0 |

No anomalies.

