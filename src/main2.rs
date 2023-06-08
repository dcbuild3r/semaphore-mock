use clap::Command;
use rand::Rng;
use ruint::Uint;
use semaphore::{
    get_supported_depths, hash_to_field,
    identity::Identity,
    poseidon_tree::{LazyPoseidonTree, PoseidonHash},
    protocol::*,
    Field,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;

#[derive(Serialize, Deserialize)]
struct GeneratedTree {
    tree_root: Uint<256, 4>,
    identity_randomness: Vec<[u8; 32]>,
}

fn main() {
    let mut cmd = Command::new("semaphore-mock")
    .arg_required_else_help(true)
    .version("0.0.1")
    .about("Generate a mock World ID semaphore tree to generate mock inclusion proofs for unit testing.")
    .subcommand(Command::new("generate-tree")
        .about("Generate a <SemaphoreTree> with a specific number of leaves and depth.")
        .arg(clap::arg!(-l --identities <IDENTITY_COUNT> "Number of identities in the tree"))
        .arg_required_else_help(true)
        .arg(clap::arg!(-d --depth <TREE_DEPTH> "Depth of the tree"))
        .arg_required_else_help(true))
    .subcommand(Command::new("prove-inclusion")
        .about("Generate a mock inclusion proof for a specific leaf index.")
        .arg(clap::arg!(-i --identity <IDENTITY_FILE> "Serialized from <Identity> into JSON object"))
        .arg_required_else_help(true));

    match cmd.get_matches_mut().subcommand() {
        Some(("generate-tree", args)) => {
            let mut rng = rand::thread_rng();

            let identity_count = args
                .get_one::<String>("identities")
                .unwrap()
                .parse::<usize>()
                .unwrap();

            // generate merkle tree
            let leaf = Field::from(0);
            let mut tree = LazyPoseidonTree::new(depth, leaf).derived();

            let mut identity_randomness = Vec::new();

            for i in 0..identity_count {
                // Generate a random 32-byte array
                let mut random_bytes = [0u8; 32];
                rng.fill(&mut random_bytes);

                identity_randomness.push(random_bytes);

                // generate identity
                let id = Identity::from_secret(&random_bytes, None);

                tree = tree.update(i, &id.commitment());
            }

            let root = tree.root();

            let generated_tree = GeneratedTree {
                tree_root: root,
                identity_randomness,
            };

            let json_tree = serde_json::to_string(&generated_tree).unwrap();

            let file_path = "out/generated_tree.json";

            // Open a file in write mode
            let mut fileo = File::create(file_path).expect("Unable to create file");

            // Write the JSON string to the file
            file.write_all(json_tree.as_bytes())
                .expect("Unable to write to file");
        }
        Some(("prove-inclusion", args)) => {
            println!("prove-inclusion")
        }
        _ => unreachable!(),
    }
}
