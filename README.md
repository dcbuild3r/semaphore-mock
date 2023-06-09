# semaphore-mock

Generate a mock World ID semaphore tree to generate mock inclusion proofs for unit testing. Doesn't require [`signup-sequencer`](https://github.com/worldcoin/signup-sequencer) and uses [`semaphore-rs`](https://github.com/worldcoin/semaphore-rs) to generate the tree and the proofs.

## Usage

Generate identities:

```bash
# Generates 100 secrets from which you can create Semaphore identities (out/random_identities.json)
cargo run --release generate-identities -identities 100
```

Prove inclusion and output the proof to json:

```bash
# Generates an inclusion proof for a given leaf index (out/proof.json)
cargo run --release prove-inclusion -i "out/random_identities.json" -tree-depth 16 --identity-index 16
```
