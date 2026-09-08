# The JDK arm: the same campaign against the JDK's own providers

Design amendment A5 (`docs/EXPERIMENT-DESIGN.md` §12) adds six targets, `jdk-*`, that drive the same
entry points in the JDK's own ML-KEM (`SunJCE`, JEP 496) and ML-DSA (`SUN`, JEP 497) providers. This
file summarizes the three campaigns; the generated reports and minimized reproducers are in
`jdk25/`, `jdk24/` and `jdk27ea/`.

| Setting | Value |
|---|---|
| Primary JVM | OpenJDK 25.0.2 (Homebrew), the current long-term-support release |
| Version-stability checks | Amazon Corretto 24.0.2 (the first release with these providers); OpenJDK 27-ea |
| BouncyCastle on the classpath | 1.85 (supplies the deterministic ML-DSA key material shared with the BouncyCastle arm) |
| Campaign | 100,000 inputs per target, seed `20260717`, 5,000 ms per-input budget, `-XX:-OmitStackTraceInFastThrow` |
| Date | 2026-09-04 |

## Headline

600,000 inputs across six targets, on each of three JVMs, produced **two distinct anomalies, both of
the same kind**: the parse-only decoders for ML-DSA-65 and ML-KEM-768 **accept a public key of the
wrong length**. Nothing else: no undocumented exception, no timeout, no forgery, on any JVM. The
outcome counts are identical on JDK 25, 24 and 27-ea to the last input; only throughput differs.

That anomaly is the `ACCEPTED` outcome of design amendment A3, the same class as the BouncyCastle 1.84
positive control, and it was predicted in A5 before the campaigns ran, from a construction-time smoke
test. The consequence differs from 1.84: BouncyCastle 1.84 threw `ArrayIndexOutOfBoundsException`
when the bogus key was used; the JDK's use-time check throws a documented `InvalidKeyException`
("Incorrect public key size" for ML-DSA, "Public key is not the correct size" for ML-KEM), so the
composed parse-then-use targets score every such input `REJECTED`. The JDK fails closed, later than
it could.

Minimized reproducers: **0 bytes** for both targets, meaning an X.509 `SubjectPublicKeyInfo` whose BIT
STRING carries an empty key is accepted by `KeyFactory.generatePublic` as an ML-DSA-65 or ML-KEM-768
public key. `CertificateFactory.generateCertificate` followed by `getPublicKey()` behaves the same
way on a certificate carrying such a key. The JDK's own Ed25519 `KeyFactory` rejects a wrong-length
key at parse time ("key length must be 32"). In the JDK source, `NamedKeyFactory` builds a
`NamedX509Key` from the raw bytes without a length check; the check lives in `ML_DSA.checkPublicKey`
(reached from `NamedSignature.engineInitVerify`) and in the ML-KEM equivalent reached from
`NamedKEM.newEncapsulator`.

## The two arms side by side (JDK 25 against BouncyCastle 1.85, same seed)

For the five key and signature targets the seed corpora, and therefore the mutation streams, are
byte-identical between the arms (`CrossArmCorpusTest`): the *i*-th input of a JDK campaign is the
*i*-th input of the BouncyCastle campaign. The decapsulation target uses a JDK-generated key pair
(JDK 24 cannot import BouncyCastle's PKCS#8 ML-KEM private key), so its inputs share lengths and
mutation choices but not bytes.

| Target | Arm | OK | REJECTED | UNEXPECTED | TIMEOUT | ACCEPTED | Distinct |
|---|---|---:|---:|---:|---:|---:|---:|
| ML-KEM-768 decap | BC | 69,848 | 30,152 | 0 | 0 | 0 | 0 |
| | JDK | 69,848 | 30,152 | 0 | 0 | 0 | 0 |
| ML-KEM-768 pubkey parse | BC | 37,312 | 62,688 | 0 | 0 | 0 | 0 |
| | JDK | 70,044 | 0 | 0 | 0 | **29,956** | **1** |
| ML-KEM-768 parse + encapsulate | BC | 37,312 | 62,688 | 0 | 0 | 0 | 0 |
| | JDK | 37,312 | 62,688 | 0 | 0 | 0 | 0 |
| ML-DSA-65 verify | BC | 10 | 99,990 | 0 | 0 | 0 | 0 |
| | JDK | 10 | 99,990 | 0 | 0 | 0 | 0 |
| ML-DSA-65 pubkey parse | BC | 70,174 | 29,826 | 0 | 0 | 0 | 0 |
| | JDK | 70,174 | 0 | 0 | 0 | **29,826** | **1** |
| ML-DSA-65 parse + verify | BC | 9 | 99,991 | 0 | 0 | 0 | 0 |
| | JDK | 9 | 99,991 | 0 | 0 | 0 | 0 |

Three things to read off this table.

1. **The two implementations reach the same final decision on every one of the 500,000 shared
   inputs** where a decision is reached: every count for the verify, decapsulate and composed targets
   is identical. Whatever a key or signature is, both providers agree on whether it is usable.
2. **They differ only in where the check happens.** On the ML-KEM parse-only target BouncyCastle
   refuses 62,688 inputs at parse time: the 29,956 wrong-length ones, and 32,732 correct-length ones
   whose content fails the FIPS 203 encapsulation-key check (a coefficient not below q). The JDK
   accepts all 70,044 correct-length inputs at parse time and refuses exactly those same 32,732 on
   `newEncapsulator`, which is why the composed counts match to the input. The JDK defers both the
   length check and the content check to the point of use; BouncyCastle does both when the key is
   decoded. For ML-DSA, whose public key has no content check, only the length check moves.
3. **The A3 rule does its job.** Scoring a wrong-length parse as `OK` because nothing was thrown
   would have recorded 59,782 silent acceptances as correct behaviour. The classifier scores them as
   the defect class they are, and the composed targets then show what that class costs on this
   provider: nothing, because the use-time check is a documented rejection. On 1.84 the same class
   cost an out-of-bounds access.

A further probe of the private-key side (JDK 25.0.2) showed the same split: the seed form of a
PKCS#8 ML-DSA-65 private key is rejected at parse time for a wrong seed length ("Cannot parse
input"), while the expandedKey form of the wrong length is accepted by `generatePrivate` and fails at
`initSign` with "Incorrect private key size". Private keys are not attacker-supplied in the threat
model of this study and are not fuzz targets here; the observation is recorded for the upstream
report.

## What this is, and is not

It is not a vulnerability. No input crashed, hung, or verified, and a wrong-length key is refused
before it is used, with an exception the API documents. It is an API-contract and robustness finding:
a `KeyFactory`, and through it a `CertificateFactory`, hands the caller a "valid" key object for a
malformed encoding, and the error surfaces later, further from its cause, in a different method,
in code that may not expect it. The JDK's own classical key factories do not behave this way. The
fix is a length check in `NamedKeyFactory` (or the `NamedX509Key` constructor), which is where
`EdDSAPublicKeyImpl` does it.

## Coverage-guided run (Jazzer, JDK 25.0.2)

Each JDK target was run under Jazzer for its two-minute budget, one target per JVM (Jazzer's JUnit
integration fuzzes one test per run). The Jazzer agent instruments JDK 25 without trouble.

| Harness | Runs in 121 s | Result |
|---|---:|---|
| `jdk-ml-kem-768-decap` | 28,251,567 | clean |
| `jdk-ml-kem-768-parse-encapsulate` | 22,014,794 | clean |
| `jdk-ml-dsa-65-verify` | 24,226,722 | clean |
| `jdk-ml-dsa-65-parse-verify` | 21,245,463 | clean |
| `jdk-ml-kem-768-pubkey-parse` | 1 | fails on the empty input: `ACCEPTED` (the finding) |
| `jdk-ml-dsa-65-pubkey-parse` | 1 | fails on the empty input: `ACCEPTED` (the finding) |

Under coverage guidance, none of the four use-path harnesses produced an undocumented exception,
a timeout, or a forgery in roughly 96 million executions combined. The two parse-only harnesses fail
on their very first input, the empty byte string, which the JDK's `KeyFactory` accepts as a public
key; that is the same zero-byte reproducer the mutation campaign minimized to, reached by the second
method in under two seconds, as the 1.84 control was. These two harnesses are opt-in
(`-Dpqcfuzz.jdk.parse=true`) so that `mvn test` stays green; the behaviour itself is pinned by
`JdkKeyLengthValidationTest`.
