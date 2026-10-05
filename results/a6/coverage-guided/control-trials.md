# Control trials from genuine seeds only (BouncyCastle 1.84, JDK 21.0.9), ten per harness

## mlDsaParseAndVerify
trial 1 | seed corpus: files: 4 | last status #41 | ml-dsa-65-parse-verify: UNEXPECTED_EXCEPTION on a 1320-byte input (java.lang.ArrayIndexOutOfBoundsException: arraycopy: length -312 is negative)
trial 2 | seed corpus: files: 4 | last status #7 | ml-dsa-65-parse-verify: UNEXPECTED_EXCEPTION on a 805-byte input (java.lang.ArrayIndexOutOfBoundsException: arraycopy: length -187 is negative)
trial 3 | seed corpus: files: 4 | last status #8 | ml-dsa-65-parse-verify: UNEXPECTED_EXCEPTION on a 1054-byte input (java.lang.ArrayIndexOutOfBoundsException: arraycopy: length -258 is negative)
trial 4 | seed corpus: files: 4 | last status #28 | ml-dsa-65-parse-verify: UNEXPECTED_EXCEPTION on a 731-byte input (java.lang.ArrayIndexOutOfBoundsException: arraycopy: length -261 is negative)
trial 5 | seed corpus: files: 4 | last status #8 | ml-dsa-65-parse-verify: UNEXPECTED_EXCEPTION on a 1418-byte input (java.lang.ArrayIndexOutOfBoundsException: arraycopy: length -214 is negative)
trial 6 | seed corpus: files: 4 | last status #7 | ml-dsa-65-parse-verify: UNEXPECTED_EXCEPTION on a 1226-byte input (java.lang.ArrayIndexOutOfBoundsException: arraycopy: length -86 is negative)
trial 7 | seed corpus: files: 4 | last status #13 | ml-dsa-65-parse-verify: UNEXPECTED_EXCEPTION on a 995-byte input (java.lang.ArrayIndexOutOfBoundsException: arraycopy: length -317 is negative)
trial 8 | seed corpus: files: 4 | last status #14 | ml-dsa-65-parse-verify: UNEXPECTED_EXCEPTION on a 1364-byte input (java.lang.ArrayIndexOutOfBoundsException: arraycopy: length -268 is negative)
trial 9 | seed corpus: files: 4 | last status #5 | ml-dsa-65-parse-verify: UNEXPECTED_EXCEPTION on a 1402-byte input (java.lang.ArrayIndexOutOfBoundsException: arraycopy: length -230 is negative)
trial 10 | seed corpus: files: 4 | last status #5 | ml-dsa-65-parse-verify: UNEXPECTED_EXCEPTION on a 1363-byte input (java.lang.ArrayIndexOutOfBoundsException: arraycopy: length -269 is negative)

## mlDsaPublicKeyParse
trial 1 | seed corpus: files: 4 | last status #5 | ml-dsa-65-pubkey-parse: ACCEPTED on a 1445-byte input (no exception)
trial 2 | seed corpus: files: 4 | last status #5 | ml-dsa-65-pubkey-parse: ACCEPTED on a 1808-byte input (no exception)
trial 3 | seed corpus: files: 4 | last status #5 | ml-dsa-65-pubkey-parse: ACCEPTED on a 1510-byte input (no exception)
trial 4 | seed corpus: files: 4 | last status #5 | ml-dsa-65-pubkey-parse: ACCEPTED on a 1183-byte input (no exception)
trial 5 | seed corpus: files: 4 | last status #5 | ml-dsa-65-pubkey-parse: ACCEPTED on a 1108-byte input (no exception)
trial 6 | seed corpus: files: 4 | last status #5 | ml-dsa-65-pubkey-parse: ACCEPTED on a 1615-byte input (no exception)
trial 7 | seed corpus: files: 4 | last status #5 | ml-dsa-65-pubkey-parse: ACCEPTED on a 986-byte input (no exception)
trial 8 | seed corpus: files: 4 | last status #5 | ml-dsa-65-pubkey-parse: ACCEPTED on a 1058-byte input (no exception)
trial 9 | seed corpus: files: 4 | last status #5 | ml-dsa-65-pubkey-parse: ACCEPTED on a 1896-byte input (no exception)
trial 10 | seed corpus: files: 4 | last status #5 | ml-dsa-65-pubkey-parse: ACCEPTED on a 1139-byte input (no exception)

## JDK parse-only harnesses (JDK 25.0.2), five trials each
jdk25-t1 jdkMlDsaPublicKeyParse exit=1 wall=3s last_status= | org.opentest4j.AssertionFailedError: jdk-ml-dsa-65-pubkey-parse: ACCEPTED on a 0-byte input (no ex
jdk25-t1 jdkMlKemPublicKeyParse exit=1 wall=2s last_status= | org.opentest4j.AssertionFailedError: jdk-ml-kem-768-pubkey-parse: ACCEPTED on a 0-byte input (no e
jdk25-t2 jdkMlDsaPublicKeyParse exit=1 wall=3s last_status= | org.opentest4j.AssertionFailedError: jdk-ml-dsa-65-pubkey-parse: ACCEPTED on a 0-byte input (no ex
jdk25-t2 jdkMlKemPublicKeyParse exit=1 wall=2s last_status= | org.opentest4j.AssertionFailedError: jdk-ml-kem-768-pubkey-parse: ACCEPTED on a 0-byte input (no e
jdk25-t3 jdkMlDsaPublicKeyParse exit=1 wall=3s last_status= | org.opentest4j.AssertionFailedError: jdk-ml-dsa-65-pubkey-parse: ACCEPTED on a 0-byte input (no ex
jdk25-t3 jdkMlKemPublicKeyParse exit=1 wall=3s last_status= | org.opentest4j.AssertionFailedError: jdk-ml-kem-768-pubkey-parse: ACCEPTED on a 0-byte input (no e
jdk25-t4 jdkMlDsaPublicKeyParse exit=1 wall=2s last_status= | org.opentest4j.AssertionFailedError: jdk-ml-dsa-65-pubkey-parse: ACCEPTED on a 0-byte input (no ex
jdk25-t4 jdkMlKemPublicKeyParse exit=1 wall=3s last_status= | org.opentest4j.AssertionFailedError: jdk-ml-kem-768-pubkey-parse: ACCEPTED on a 0-byte input (no e
jdk25-t5 jdkMlDsaPublicKeyParse exit=1 wall=2s last_status= | org.opentest4j.AssertionFailedError: jdk-ml-dsa-65-pubkey-parse: ACCEPTED on a 0-byte input (no ex
jdk25-t5 jdkMlKemPublicKeyParse exit=1 wall=3s last_status= | org.opentest4j.AssertionFailedError: jdk-ml-kem-768-pubkey-parse: ACCEPTED on a 0-byte input (no e
