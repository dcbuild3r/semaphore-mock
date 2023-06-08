use clap::Parser;
use rand::Rng;
use semaphore::{
    hash_to_field, identity::Identity, poseidon_tree::LazyPoseidonTree, protocol::*, Field,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
struct IdentityRandomness {
    secrets_vec: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Parser)]
#[clap(rename_all = "kebab-case")]
enum Args {
    /// Generate random identities to be inserted into a <SemaphoreTree>
    GenerateIdentities {
        #[clap(short, long)]
        identities: usize,
    },
    /// Generate a tree and a mock inclusion proof for a specific leaf index.
    ProveInclusion {
        #[clap(short, long)]
        identities: PathBuf,

        #[clap(short, long)]
        tree_depth: usize,

        #[clap(long)]
        identity_index: usize,
    },
}

fn read_file_to_json_string(file_path: PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let json_string = serde_json::to_string(&contents)?;
    Ok(json_string)
}

fn main() {
    let args = Args::parse();

    match args {
        Args::GenerateIdentities { identities } => {
            let mut rng = rand::thread_rng();

            let mut identity_randomness = Vec::new();

            for _ in 0..identities {
                // Generate a random 32-byte array
                let mut random_bytes = [0u8; 32];
                rng.fill(&mut random_bytes);

                identity_randomness.push(random_bytes);
            }

            let identity_randomness = IdentityRandomness {
                secrets_vec: identity_randomness,
            };

            let json_tree = serde_json::to_string(&identity_randomness).unwrap();

            let file_path = "out/random_identities.json";

            // Open a file in write mode
            let mut file = File::create(file_path).expect("Unable to create file");

            // Write the JSON string to the file
            file.write_all(json_tree.as_bytes())
                .expect("Unable to write to file");
        }
        Args::ProveInclusion {
            identities,
            identity_index,
            tree_depth,
        } => {
            let identities_json = read_file_to_json_string(identities).unwrap();

            let identities: IdentityRandomness = serde_json::from_str(&identities_json).unwrap();

            // generate merkle tree
            let leaf = Field::from(0);
            let mut tree = LazyPoseidonTree::new(tree_depth, leaf).derived();

            let mut identity_vec = Vec::<Identity>::new();

            for i in 0..identities.secrets_vec.len() {
                let id = Identity::from_secret(&identities.secrets_vec[i], None);

                tree = tree.update(i, &id.commitment());

                identity_vec.push(id);
            }

            let root = tree.root();

            let merkle_proof = tree.proof(identity_index);

            let selected_identity = &identity_vec[identity_index];

            // change signal and external_nullifier here
            let signal_hash = hash_to_field(b"xxx");
            let external_nullifier_hash = hash_to_field(b"appId");

            let nullifier_hash =
                generate_nullifier_hash(selected_identity, external_nullifier_hash);

            let proof = generate_proof(
                selected_identity,
                &merkle_proof,
                external_nullifier_hash,
                signal_hash,
            )
            .unwrap();
            let success = verify_proof(
                root,
                nullifier_hash,
                signal_hash,
                external_nullifier_hash,
                &proof,
                tree_depth,
            )
            .unwrap();

            assert!(success);
        }
    }
}
