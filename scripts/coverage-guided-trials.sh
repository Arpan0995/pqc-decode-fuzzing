#!/bin/bash
# Repeated coverage-guided trials (design amendment A7).
#
# Runs every BouncyCastle harness of PqcDecodeFuzzTest for its configured duration (two minutes), TRIALS
# times, against one BouncyCastle version, each trial in a fresh JVM from the committed seeds with no
# generated corpus carried over. Keeps the full Maven output of every trial, a one-line summary per trial,
# and the libFuzzer status lines (INITED, NEW, REDUCE, pulse, DONE), from which the execution count at
# which coverage last grew can be read off.
#
#   scripts/coverage-guided-trials.sh <bouncycastle.version> <output-dir> [trials]
#
# Run from the repository root. Set JAVA_HOME to the JDK the trials should use (the A7 runs used
# OpenJDK 21.0.9). Two versions can run side by side from two git worktrees; never from one.
set -u
VER=${1:?bouncycastle.version}; OUT=${2:?output dir}; TRIALS=${3:-5}
H=(mlKemDecap mlKemPublicKeyParse mlKemParseAndEncapsulate mlDsaVerify mlDsaPublicKeyParse mlDsaParseAndVerify slhDsaVerify slhDsaPublicKeyParse slhDsaParseAndVerify)
mkdir -p "$OUT"
for t in $(seq 1 "$TRIALS"); do
  for h in "${H[@]}"; do
    rm -rf .cifuzz-corpus
    full="$OUT/$h-t$t.full.log"
    start=$(date +%s)
    JAZZER_FUZZ=1 mvn test -Dtest="PqcDecodeFuzzTest#$h" -Dbouncycastle.version="$VER" -Dsurefire.failIfNoSpecifiedTests=false > "$full" 2>&1
    rc=$?; end=$(date +%s)
    done_line=$(grep -E '^#[0-9]+[[:space:]]+DONE' "$full" | tail -1)
    echo "bc$VER $h t$t exit=$rc wall=$((end-start))s | $done_line" >> "$OUT/summary.log"
    grep -E '^#[0-9]+[[:space:]]+(INITED|NEW|REDUCE|pulse|DONE)|^INFO: |seed corpus|Tests run' "$full" > "$OUT/$h-t$t.log"
    # Jazzer writes findings into the seed directories and Maven keeps copies under target/; sweep both.
    git status --porcelain --untracked-files=all -- src/test/resources | awk '{print $2}' | while read -r f; do rm -f "$f"; done
    find target/test-classes/org/pqcfuzz/fuzz -type f -path '*Inputs*' ! -name 'seed-*' -delete 2>/dev/null
    rm -rf .cifuzz-corpus
  done
done
echo ALLDONE >> "$OUT/summary.log"
