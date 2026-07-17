# The BouncyCastle 1.84 Positive Control

**What this is.** The study reports on BouncyCastle 1.85 (current). 1.84 is kept as a *positive
control*: it carries a real defect that 1.85 fixes, so running the identical harness against both
versions demonstrates that the harness can detect this defect class on this code path. Without it, the
null result on 1.85 would rest on nothing but the assertion that the harness works.

**There is nothing to disclose.** BouncyCastle fixed this in 1.85 before this study existed. The value
here is methodological, not a vulnerability report. Users of 1.84 should upgrade.

---

## The defect

`org.bouncycastle.crypto.params.MLDSAPublicKeyParameters(MLDSAParameters, byte[])` performs **no length
validation** on the encoding it is given. An ML-DSA-65 public key is 1952 bytes: a 32-byte `rho`
followed by the packed `t1` vector. In 1.84 the constructor slices `rho` off the front and treats
*whatever remains* as `t1`, of any size. It therefore accepts:

| Encoding | 1.84 | 1.85 |
|---|---|---|
| 0–32 bytes | `IllegalArgumentException: 32 > 0` (incidental — see below) | `IllegalArgumentException: 'encoding' has invalid length` |
| **33 bytes** | **accepted** | rejected |
| **100 bytes** | **accepted** | rejected |
| **1951 bytes** (one short) | **accepted** | rejected |
| 1952 bytes (correct) | accepted | accepted |
| **1953 bytes** (one long) | **accepted** | rejected |
| **1 MiB** | **accepted** | rejected |

Note what the short-input rejection in 1.84 actually is. The message `32 > 0` is
`java.util.Arrays.copyOfRange`'s own format for `from > to`: the decoder is not checking anything, it is
calling `copyOfRange(encoding, 32, encoding.length)` and being saved by that method's argument contract.
There is no length check to speak of — inputs under 33 bytes fail by accident, and everything above
sails through.

### Why silent acceptance is the interesting part

Accepting a malformed encoding is worse than throwing on it. The caller gets an object that looks like a
public key, believes the decode succeeded, and carries on. The error surfaces later, further from its
cause:

```
MLDSAPublicKeyParameters bogus = new MLDSAPublicKeyParameters(ml_dsa_65, new byte[33]);  // fine, apparently
signer.init(false, bogus);
signer.verifySignature(genuineSignature);
// java.lang.ArrayIndexOutOfBoundsException: arraycopy: length -319 is negative
//   at org.bouncycastle.crypto.signers.mldsa.Packing.unpackPublicKey
```

`Packing.unpackPublicKey` computes a segment length from the (unvalidated) encoding size, gets a
negative number, and hands it to `arraycopy`. The exception names neither the real problem (a 33-byte
key) nor the code that let it through.

### Reachability

This is in the **current, non-deprecated** API — `org.bouncycastle.crypto.params`, which
`PublicKeyFactory` returns when parsing an X.509 `SubjectPublicKeyInfo`. It is not confined to the
deprecated `org.bouncycastle.pqc.crypto.mldsa` shim (which has it too). A client verifying a peer's
ML-DSA certificate chain runs exactly this sequence on bytes the peer chose, so on 1.84 a malformed key
in a certificate yields an `ArrayIndexOutOfBoundsException` where a clean rejection belongs — a
denial-of-service vector on an unauthenticated path.

ML-KEM and SLH-DSA validate their encoding lengths correctly in **both** versions. ML-DSA was the
outlier.

## What it takes to reach it

**A valid signature and an invalid key.** ML-DSA verification checks the signature's own structure
before it unpacks the public key, so a malformed signature is refused early and the bogus key is never
touched — feeding an all-zero signature alongside a 33-byte key returns `false` and throws nothing at
all. Only a well-formed signature carries execution as far as `unpackPublicKey`.

This is why the study fuzzes composed paths (design §12, A2) and not just individual entry points:

- `ml-dsa-65-pubkey-parse` (parse alone) records the defect only as `ACCEPTED` — the decoder swallows
  the input and reports success. No exception, nothing to see.
- `ml-dsa-65-parse-verify` (parse, then verify with a genuine signature) produces the
  `ArrayIndexOutOfBoundsException`.

Fuzzing both entry points separately, with random bytes on each, cannot construct the pairing. The
original six pre-registered targets would have reported 1.84 clean.

## Results

Both fuzzing methods find it independently, from a 4-byte-different starting point, and converge on the
same minimized input.

| | Mutation campaign | Jazzer (coverage-guided) |
|---|---|---|
| Time to find | within 400 inputs | < 2 seconds |
| Minimized reproducer | 33 zero bytes | 33 zero bytes |

The 33-byte reproducer is the boundary exactly: 32 bytes of `rho` plus the single byte that makes
`copyOfRange` succeed and the missing check bite.

Campaign output is in [`control-bc184/CAMPAIGN-RESULTS.md`](control-bc184/CAMPAIGN-RESULTS.md), with
reproducers under [`control-bc184/corpus/`](control-bc184/corpus/). Reproduce with:

```bash
mvn test -Dbouncycastle.version=1.84                                          # the control, pinned as tests
JAZZER_FUZZ=1 mvn test -Dbouncycastle.version=1.84 -Dtest=PqcDecodeFuzzTest   # expected to FAIL
java -XX:-OmitStackTraceInFastThrow -cp target/classes:... org.pqcfuzz.FuzzCampaign \
    --targets=ml-dsa-65-parse-verify --inputs=400 --out=/tmp/control
```

`MlDsaKeyLengthValidationTest` pins both halves of the claim as an executable specification: on 1.84 the
wrong-length key is accepted and using it throws; on 1.85 it is rejected. Each half is skipped on the
version it does not describe, so the suite is green on both.

## How the hypotheses land

The 1.84/1.85 pair separates the pre-registered hypotheses in a way worth reporting, because the defect
does not land where H2 expected it to:

| | 1.85 (under test) | 1.84 (control) |
|---|---|---|
| **H1** (verify paths are total) | supported | **not supported** — the composed verify path throws |
| **H2** (decoders throw undocumented exceptions) | not supported | not supported — *the decoder never throws at all; it accepts silently* |
| **H3** (ML-KEM decap never throws at correct length) | supported | supported |
| **H4** (no hangs) | supported | supported |

H2 predicted the classic decoder-fuzzing yield: malformed input in, undocumented exception out. The real
defect is the shape H2 did not consider — a decoder with no check, failing by *accepting* — and the
exception it eventually causes is attributed to a verify target, which is why H1 is the hypothesis that
breaks. Pre-registering H2 is what makes that visible: the prediction was specific enough to be wrong in
an informative direction, rather than vague enough to accommodate the result after the fact.
