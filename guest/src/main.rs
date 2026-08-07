// Follows zkp_ecc program/src/main.rs (CC BY 4.0). See NOTICE.
#![no_main]
sp1_zkvm::entrypoint!(main);

mod curve;
mod ops;
mod sim;

use ops::{Packed, RawOp, Slot, OP_BYTES};
use ruint::aliases::U256;
use sha2::{Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use sim::{Coins, Sim};

const NUM_TESTS: usize = 9024;
const BATCH: usize = 64;

/// Byte-exact with the evaluator; any drift grades a different test set.
const FS_DOMAIN: &[u8] = b"quantum_ecc-fiat-shamir-v2";

struct Transcript(sha3::Shake256Reader);

impl Coins for Transcript {
    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.0.read(&mut buf);
        u64::from_le_bytes(buf)
    }
}

#[derive(Clone, Copy)]
struct Claim {
    max_toffoli: u64,
    max_qubits: u64,
    max_ops: u64,
}

pub fn main() {
    let max_toffoli = sp1_zkvm::io::read::<u64>();
    let max_qubits = sp1_zkvm::io::read::<u64>();
    let max_ops = sp1_zkvm::io::read::<u64>();
    let claim = Claim { max_toffoli, max_qubits, max_ops };

    let raw: Vec<u8> = sp1_zkvm::io::read_vec();
    assert!(raw.len() % OP_BYTES == 0, "op stream is not a whole number of records");
    let n_ops = raw.len() / OP_BYTES;
    assert!(n_ops as u64 <= claim.max_ops, "operation count exceeds the claimed bound");

    let mut commit = Sha256::new();
    Digest::update(&mut commit, (n_ops as u64).to_le_bytes());

    let mut fs = Shake256::default();
    fs.update(FS_DOMAIN);
    fs.update(&(n_ops as u64).to_le_bytes());

    // Two passes, no decoded Vec: the zkVM allocator never frees, so peak is cumulative.
    let mut layout_acc = ops::Analyzer::new();
    for i in 0..n_ops {
        let rec = &raw[i * OP_BYTES..(i + 1) * OP_BYTES];
        Digest::update(&mut commit, rec);
        let op = RawOp::decode(rec);
        fs.update(&op.fs_bytes());
        layout_acc.feed(&op);
    }
    let circuit_sha256: [u8; 32] = commit.finalize().into();
    let mut xof = Transcript(fs.finalize_xof());
    let layout = layout_acc.finish();

    assert!(layout.fits(), "circuit is too wide for the packed op encoding");
    assert!(layout.num_qubits <= claim.max_qubits, "qubit count exceeds the claimed bound");
    ops::check_register_composition(&layout).expect("register composition");

    let mut packed: Vec<Packed> = Vec::with_capacity(n_ops);
    for i in 0..n_ops {
        let op = RawOp::decode(&raw[i * OP_BYTES..(i + 1) * OP_BYTES]);
        ops::validate_one(&op, &layout).expect("op validation");
        packed.push(ops::pack_one(&op));
    }

    let regs = &layout.registers;

    let mut targets = Vec::with_capacity(NUM_TESTS);
    let mut offsets = Vec::with_capacity(NUM_TESTS);
    let mut expected = Vec::with_capacity(NUM_TESTS);
    for _ in 0..NUM_TESTS {
        let mut b0 = [0u8; 32];
        let mut b1 = [0u8; 32];
        xof.0.read(&mut b0);
        xof.0.read(&mut b1);
        let t = curve::mul_generator(U256::from_le_bytes(b0));
        let o = curve::mul_generator(U256::from_le_bytes(b1));
        if t.0 == o.0 || curve::is_inf(t.0, t.1) || curve::is_inf(o.0, o.1) {
            continue;
        }
        expected.push(curve::add(t.0, t.1, o.0, o.1));
        targets.push(t);
        offsets.push(o);
    }
    let n = targets.len();
    assert!(n == NUM_TESTS, "graded count is not the full test set");

    let mut s = Sim::new(layout.num_qubits as usize, layout.num_bits as usize);
    let num_batches = (n + BATCH - 1) / BATCH;

    for batch in 0..num_batches {
        let bs = BATCH.min(n - batch * BATCH);
        let cond_mask: u64 = if bs == 64 { u64::MAX } else { (1u64 << bs) - 1 };

        s.clear_for_shot();
        for shot in 0..bs {
            let i = batch * BATCH + shot;
            s.set_register(&regs[0], targets[i].0, shot);
            s.set_register(&regs[1], targets[i].1, shot);
            s.set_register(&regs[2], offsets[i].0, shot);
            s.set_register(&regs[3], offsets[i].1, shot);
        }

        s.apply(&packed, &mut xof);

        for shot in 0..bs {
            let i = batch * BATCH + shot;
            assert!(
                s.get_register(&regs[0], shot) == expected[i].0
                    && s.get_register(&regs[1], shot) == expected[i].1,
                "classical mismatch"
            );
        }

        assert!(s.phase & cond_mask == 0, "phase garbage");

        for reg in &regs[..4] {
            for slot in reg {
                if let Slot::Qubit(q) = *slot {
                    s.qubits[q as usize] = 0;
                }
            }
        }
        for q in 0..layout.num_qubits as usize {
            assert!(s.qubits[q] & cond_mask == 0, "ancilla garbage");
        }
    }

    let avg_toffoli_rounded = (2 * s.toffoli + n.max(1) as u64) / (2 * n.max(1) as u64);
    assert!(avg_toffoli_rounded <= claim.max_toffoli, "Toffoli count exceeds the claimed bound");

    sp1_zkvm::io::commit_slice(&circuit_sha256);
    sp1_zkvm::io::commit(&claim.max_toffoli);
    sp1_zkvm::io::commit(&claim.max_qubits);
    sp1_zkvm::io::commit(&claim.max_ops);
    sp1_zkvm::io::commit(&(n as u64));
}
