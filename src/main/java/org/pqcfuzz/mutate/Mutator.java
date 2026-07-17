package org.pqcfuzz.mutate;

import java.util.List;
import java.util.random.RandomGenerator;

/**
 * Generates mutated inputs for one target by drawing a seed and a {@link Mutation} uniformly at random.
 *
 * <p>Uniform choice is deliberate. A weighted schedule would need a prior about which strategies pay
 * off, and having none is the point of the exercise — a flat schedule keeps the per-strategy outcome
 * counts directly comparable and lets the results say which strategies mattered. That is also the
 * limitation this method is honest about: without coverage feedback there is nothing steering the
 * search, which is why the Jazzer harnesses exist alongside it.
 *
 * <p>Not thread-safe: give each campaign thread its own instance with its own seeded generator.
 */
public final class Mutator {

    private static final Mutation[] STRATEGIES = Mutation.values();

    private final List<byte[]> seeds;
    private final int nominalLength;
    private final RandomGenerator rng;

    public Mutator(List<byte[]> seeds, int nominalLength, RandomGenerator rng) {
        if (seeds.isEmpty()) {
            throw new IllegalArgumentException("A mutator needs at least one seed to mutate");
        }
        this.seeds = List.copyOf(seeds);
        this.nominalLength = nominalLength;
        this.rng = rng;
    }

    /** Draw one mutated input. */
    public MutatedInput next() {
        int seedIndex = rng.nextInt(seeds.size());
        Mutation mutation = STRATEGIES[rng.nextInt(STRATEGIES.length)];
        byte[] bytes = mutation.apply(seeds.get(seedIndex), nominalLength, rng);
        return new MutatedInput(bytes, mutation, seedIndex);
    }
}
