# Per-input comparison of the two arms (design amendment A7)

Generated 2026-10-05T16:54:25.757445Z by `org.pqcfuzz.run.ArmDiff`.

| Setting | Value |
|---|---|
| Label | Bouncy Castle 1.85 against the JDK providers of OpenJDK 25.0.2 |
| JVM | OpenJDK 64-Bit Server VM 25.0.2 |
| Campaign seed | `20260717` |
| Inputs per pair | 100,000 |
| Per-input timeout | 5000 ms |

For every input the mutation stream is the one the campaign used under this seed, and the two outcomes are the campaign's own classifier applied to each arm. A cell `X / Y` counts inputs that Bouncy Castle scored `X` and the JDK scored `Y`.

## `ml-kem-768-pubkey-parse` against `jdk-ml-kem-768-pubkey-parse`

Seed corpora byte-identical: yes; nominal length 1184 bytes; 4 seed inputs.

| Bouncy Castle / JDK | Inputs | Of which wrong-length |
|---|---:|---:|
| `OK / OK` | 37,312 | 0 |
| `REJECTED / ACCEPTED` | 29,956 | 29,956 |
| `REJECTED / OK` | 32,732 | 0 |

**Disagreements: 62,688 of 100,000** (29,956 on wrong-length inputs, 32,732 on correct-length inputs).

First disagreements: input 1 (CHUNK_RANDOMIZE, 1184 bytes): REJECTED / OK; input 2 (CHUNK_RANDOMIZE, 1184 bytes): REJECTED / OK; input 3 (EXTEND, 1934 bytes): REJECTED / ACCEPTED; input 6 (LENGTH_EDGE, 1048576 bytes): REJECTED / ACCEPTED; input 8 (RANDOM, 1184 bytes): REJECTED / OK.

## `ml-kem-768-parse-encapsulate` against `jdk-ml-kem-768-parse-encapsulate`

Seed corpora byte-identical: yes; nominal length 1184 bytes; 4 seed inputs.

| Bouncy Castle / JDK | Inputs | Of which wrong-length |
|---|---:|---:|
| `OK / OK` | 37,312 | 0 |
| `REJECTED / REJECTED` | 62,688 | 29,956 |

**Disagreements: 0 of 100,000** (0 on wrong-length inputs, 0 on correct-length inputs).

## `ml-dsa-65-verify` against `jdk-ml-dsa-65-verify`

Seed corpora byte-identical: yes; nominal length 3309 bytes; 4 seed inputs.

| Bouncy Castle / JDK | Inputs | Of which wrong-length |
|---|---:|---:|
| `OK / OK` | 10 | 0 |
| `REJECTED / REJECTED` | 99,990 | 30,015 |

**Disagreements: 0 of 100,000** (0 on wrong-length inputs, 0 on correct-length inputs).

## `ml-dsa-65-pubkey-parse` against `jdk-ml-dsa-65-pubkey-parse`

Seed corpora byte-identical: yes; nominal length 1952 bytes; 4 seed inputs.

| Bouncy Castle / JDK | Inputs | Of which wrong-length |
|---|---:|---:|
| `OK / OK` | 70,174 | 0 |
| `REJECTED / ACCEPTED` | 29,826 | 29,826 |

**Disagreements: 29,826 of 100,000** (29,826 on wrong-length inputs, 0 on correct-length inputs).

First disagreements: input 3 (EXTEND, 3886 bytes): REJECTED / ACCEPTED; input 6 (TRUNCATE, 1924 bytes): REJECTED / ACCEPTED; input 7 (EXTEND, 2703 bytes): REJECTED / ACCEPTED; input 8 (EXTEND, 3620 bytes): REJECTED / ACCEPTED; input 9 (TRUNCATE, 916 bytes): REJECTED / ACCEPTED.

## `ml-dsa-65-parse-verify` against `jdk-ml-dsa-65-parse-verify`

Seed corpora byte-identical: yes; nominal length 1952 bytes; 4 seed inputs.

| Bouncy Castle / JDK | Inputs | Of which wrong-length |
|---|---:|---:|
| `OK / OK` | 9 | 0 |
| `REJECTED / REJECTED` | 99,991 | 29,826 |

**Disagreements: 0 of 100,000** (0 on wrong-length inputs, 0 on correct-length inputs).

## Total

92,514 disagreements over 500,000 shared inputs.
