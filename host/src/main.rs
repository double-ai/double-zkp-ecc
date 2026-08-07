use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, HashableKey, ProvingKey, SP1Stdin,
};
use std::{fs, path::PathBuf};

fn elf() -> sp1_sdk::Elf {
    include_elf!("point-add-zk-guest")
}

// The shipped ELF is the one the published key was computed from.
fn elf_or_shipped(path: &Option<PathBuf>) -> Result<sp1_sdk::Elf> {
    match path {
        Some(p) => Ok(sp1_sdk::Elf::from(
            fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        )),
        None => Ok(elf()),
    }
}

const OP_BYTES: usize = 56;
const MAGIC: &[u8; 8] = b"QECCOPSZ";

const CLAIM_TOFFOLI: u64 = 993_181;
const CLAIM_QUBITS: u64 = 1_205;
const CLAIM_OPS: u64 = 11_000_000;
const CLAIM_TESTS: u64 = 9_024;
const CLAIM_VKEY: &str =
    "0x0020a7c8b837a0f061470bab20b9c984ef7fdc4372905e257e85d6c459ba9fec";
const CLAIM_CIRCUIT_SHA256: &str =
    "325088b199357b6da22c710dc8f8c7cf3fa4c7be6fef067754c8d91b88c76186";

#[derive(Parser)]
#[command(about = "Zero-knowledge proof of point-addition circuit resource costs")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Execute {
        #[arg(long)]
        ops: PathBuf,
        #[arg(long)]
        max_toffoli: u64,
        #[arg(long)]
        max_qubits: u64,
        #[arg(long)]
        max_ops: u64,
    },
    Prove {
        #[arg(long)]
        ops: PathBuf,
        #[arg(long)]
        max_toffoli: u64,
        #[arg(long)]
        max_qubits: u64,
        #[arg(long)]
        max_ops: u64,
        #[arg(long)]
        out: PathBuf,
    },
    Verify {
        #[arg(long, default_value = "../artifacts/proof.bin")]
        proof: PathBuf,
        /// Defaults to the shipped ELF.
        #[arg(long, default_value = "../artifacts/point-add-zk-guest.elf")]
        elf: Option<PathBuf>,
    },
    Vk {
        #[arg(long, default_value = "../artifacts/point-add-zk-guest.elf")]
        elf: Option<PathBuf>,
    },
    Statement {
        #[arg(long, default_value = "../artifacts/proof.bin")]
        proof: PathBuf,
        /// Defaults to the shipped ELF.
        #[arg(long, default_value = "../artifacts/point-add-zk-guest.elf")]
        elf: Option<PathBuf>,
    },
}

fn load_ops(path: &PathBuf) -> Result<Vec<u8>> {
    let blob = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if blob.len() < 16 || &blob[0..8] != MAGIC {
        bail!("not an ops.bin (bad magic)");
    }
    let declared = u64::from_le_bytes(blob[8..16].try_into().unwrap()) as usize;
    let body = zstd::stream::decode_all(&blob[16..]).context("zstd decode")?;
    if body.len() != declared * OP_BYTES {
        bail!("header declares {declared} ops but body holds {}", body.len() / OP_BYTES);
    }
    Ok(body)
}

fn stdin_for(body: Vec<u8>, t: u64, q: u64, o: u64) -> SP1Stdin {
    let mut s = SP1Stdin::new();
    s.write(&t);
    s.write(&q);
    s.write(&o);
    s.write_vec(body);
    s
}

// A proof is only ours if the key is ours and the proof is the wrapped, zero-knowledge kind.
fn check_provenance(proof: &sp1_sdk::SP1ProofWithPublicValues, vk_hex: &str) -> Result<()> {
    if vk_hex != CLAIM_VKEY {
        bail!("wrong program: key {vk_hex} is not the published {CLAIM_VKEY}");
    }
    if !matches!(proof.proof, sp1_sdk::SP1Proof::Groth16(_)) {
        bail!("not a Groth16 proof; core and compressed proofs are not zero-knowledge");
    }
    Ok(())
}

fn check_statement(
    hash: &[u8; 32], toffoli: u64, qubits: u64, ops: u64, graded: u64,
) -> Result<()> {
    if toffoli != CLAIM_TOFFOLI
        || qubits != CLAIM_QUBITS
        || ops != CLAIM_OPS
        || graded != CLAIM_TESTS
        || hex::encode(hash) != CLAIM_CIRCUIT_SHA256
    {
        bail!(
            "PROOF IS FOR A DIFFERENT STATEMENT: committed {toffoli}/{qubits}/{ops} over \
             {graded} tests, circuit 0x{}",
            hex::encode(hash)
        );
    }
    Ok(())
}

fn commitment(body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    Digest::update(&mut h, ((body.len() / OP_BYTES) as u64).to_le_bytes());
    Digest::update(&mut h, body);
    h.finalize().into()
}

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    match Cli::parse().cmd {
        Cmd::Vk { elf: path } => {
            let e = elf_or_shipped(&path)?;
            let client = ProverClient::from_env();
            let pk = client.setup(e).map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("{}", pk.verifying_key().bytes32());
        }

        Cmd::Execute { ops, max_toffoli, max_qubits, max_ops } => {
            let body = load_ops(&ops)?;
            println!("circuit SHA-256 : 0x{}", hex::encode(commitment(&body)));
            let client = ProverClient::from_env();
            let (pv, report) = client
                .execute(elf(), stdin_for(body, max_toffoli, max_qubits, max_ops))
                .run()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let n = pv.as_slice().len();
            if n != 64 {
                bail!("GUEST FAILED — committed {n} bytes, expected 64 (it panicked)");
            }
            println!("GUEST OK — every assertion held.");
            println!("cycles: {}", report.total_instruction_count());
        }

        Cmd::Prove { ops, max_toffoli, max_qubits, max_ops, out } => {
            let body = load_ops(&ops)?;
            let hash = commitment(&body);

            let client = ProverClient::from_env();
            let pk = client.setup(elf()).map_err(|e| anyhow::anyhow!("{e}"))?;
            let vk = pk.verifying_key().clone();

            // Groth16 only: core and compressed proofs are not zero-knowledge and
            // would disclose the witness, which is the circuit.
            let proof = client
                .prove(&pk, stdin_for(body, max_toffoli, max_qubits, max_ops))
                .groth16()
                .run()
                .map_err(|e| anyhow::anyhow!("proving failed: {e}"))?;

            client.verify(&proof, &vk, None).context("self-verification failed")?;

            if out.join("proof.bin").exists() {
                bail!("{} already holds a proof.bin; refusing to overwrite published artifacts", out.display());
            }
            fs::create_dir_all(&out)?;
            proof.save(out.join("proof.bin")).map_err(|e| anyhow::anyhow!("{e}"))?;
            fs::write(out.join("vk.txt"), format!("{}\n", vk.bytes32()))?;
            fs::write(out.join("circuit_sha256.txt"), format!("0x{}\n", hex::encode(hash)))?;
            // The ELF is what the key hashes.
            fs::write(out.join("point-add-zk-guest.elf"), elf().as_ref())?;

            println!("circuit SHA-256 : 0x{}", hex::encode(hash));
            println!("verification key: {}", vk.bytes32());
            println!("written to      : {}", out.display());
        }

        Cmd::Statement { proof, elf: elf_path } => {
            let proof = sp1_sdk::SP1ProofWithPublicValues::load(&proof)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let client = ProverClient::from_env();
            let pk = client.setup(elf_or_shipped(&elf_path)?).map_err(|e| anyhow::anyhow!("{e}"))?;
            let vk = pk.verifying_key();
            client.verify(&proof, vk, None).context("refusing to print an invalid proof")?;
            check_provenance(&proof, &vk.bytes32())?;

            let mut pv = proof.public_values.clone();
            let circuit_sha256: [u8; 32] = pv.read();
            let max_toffoli: u64 = pv.read();
            let max_qubits: u64 = pv.read();
            let max_ops: u64 = pv.read();
            let graded: u64 = pv.read();
            check_statement(&circuit_sha256, max_toffoli, max_qubits, max_ops, graded)?;

            println!("Zero Knowledge Proof Statement (doubleAI, WarpSpeed) We possess a quantum");
            println!("kickmix circuit C_warpspeed (uniquely committed to via its cryptographic");
            println!("hash) with resource counts of at most:");
            println!("  * {max_toffoli} non-Clifford gates (CCX + CCZ), average executed per shot, rounded");
            println!("  * {max_qubits} logical qubits");
            println!("  * {max_ops} total operations");
            println!("that correctly computes point addition on the elliptic curve secp256k1");
            println!("across all {graded} pseudo-random distinct-x inputs deterministically derived");
            println!("from the circuit's own hash.\n");
            println!("Circuit SHA-256 Hash:\n0x{}\n", hex::encode(circuit_sha256));
            println!("Groth16 Proof Bytes:\n0x{}\n", hex::encode(proof.bytes()));
            println!("Verification Key:\n{}", vk.bytes32());
        }

        Cmd::Verify { proof, elf: elf_path } => {
            let proof = sp1_sdk::SP1ProofWithPublicValues::load(&proof)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let client = ProverClient::from_env();
            let pk = client.setup(elf_or_shipped(&elf_path)?).map_err(|e| anyhow::anyhow!("{e}"))?;
            let vk = pk.verifying_key();
            client.verify(&proof, vk, None).context("PROOF INVALID")?;
            check_provenance(&proof, &vk.bytes32())?;

            let mut pv = proof.public_values.clone();
            let circuit_sha256: [u8; 32] = pv.read();
            let max_toffoli: u64 = pv.read();
            let max_qubits: u64 = pv.read();
            let max_ops: u64 = pv.read();
            let graded: u64 = pv.read();

            check_statement(&circuit_sha256, max_toffoli, max_qubits, max_ops, graded)?;
            println!("PROOF VALID against verification key {}\n", vk.bytes32());
            println!("We possess a quantum kickmix circuit (committed to via its cryptographic");
            println!("hash) with resource counts of at most:");
            println!("  * {max_toffoli} non-Clifford gates (CCX + CCZ), average executed per shot, rounded");
            println!("  * {max_qubits} logical qubits");
            println!("  * {max_ops} total operations");
            println!("that correctly computes point addition on the elliptic curve secp256k1");
            println!("across all {graded} pseudo-random distinct-x inputs deterministically derived");
            println!("from the circuit's own hash.\n");
            println!("Circuit SHA-256: 0x{}", hex::encode(circuit_sha256));
        }
    }
    Ok(())
}
