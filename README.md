# pqc-decode-fuzzing

**Does it reject cleanly?** A fuzzing study of the robustness of Java post-quantum **decode and verify**
paths — the first code an adversary reaches when a peer speaks PQC.

A server decapsulates a client's ML-KEM ciphertext; a client verifies a server's ML-DSA or SLH-DSA
signature; both parse encoded public keys from certificates and key-shares. These paths must be robust
to hostile bytes: a verify function should return "invalid" (never throw, hang, or accept a forgery),
and a decoder should fail predictably (a documented exception, never an `ArrayIndexOutOfBounds`,
`NegativeArraySize`, unbounded allocation, or a non-terminating loop). This project fuzzes those paths
in BouncyCastle 1.84 and classifies every outcome.

## Status

Design phase. Pre-registered design (targets, research questions, outcome classification, hypotheses)
in [`docs/EXPERIMENT-DESIGN.md`](docs/EXPERIMENT-DESIGN.md).

## Approach

Two complementary methods over the same targets (ML-KEM decapsulation and key parse; ML-DSA/SLH-DSA
verify and key parse):

1. **Portable mutation campaign** (pure Java, the runnable workhorse): seed from valid encodings, apply
   structured mutations, drive each target under a timeout, and classify every outcome as `REJECTED`,
   `UNEXPECTED_EXCEPTION`, `TIMEOUT`, `ACCEPTED` (forgery), or `OK`, de-duplicating anomaly signatures
   and saving minimal reproducers.
2. **Coverage-guided fuzzing (Jazzer)**: JUnit5 `@FuzzTest` harnesses driving the same targets with
   libFuzzer-based JVM coverage feedback.

## Toolchain

Java 21 (pinned OpenJDK 21); BouncyCastle `bcprov-jdk18on` 1.84; Jazzer (`jazzer-junit`) 0.22.1;
Maven. Apple-Silicon runs are exploratory for throughput; robustness findings are host-independent.

## Layout

```
docs/EXPERIMENT-DESIGN.md   Pre-registered design (read this first)
fuzz/ (src)                 Targets, mutation engine, campaign runner, Jazzer harnesses
results/                    Outcome summaries + curated corpus of interesting inputs
```

## License

Apache-2.0 (see `LICENSE`).
