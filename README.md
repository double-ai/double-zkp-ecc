# Zero-knowledge proof of resource costs — secp256k1 point addition

This is a zero-knowledge proof that our WarpSpeed quantum circuit exists and achieves the resource cost we claim, without revealing the circuit itself.
We publish the proof rather than the circuit, so the result is independently verifiable while the circuit remains private. 
For more details, see https://www.doubleai.com/research/warpspeed-discovers-record-breaking-ecdsa-cracking-circuit

**doubleAI** · produced by WarpSpeed

> **Zero Knowledge Proof Statement (doubleAI, WarpSpeed).** We possess a quantum kickmix circuit
> `C_warpspeed` (uniquely committed to via its cryptographic hash) with resource counts of at most:
>
> * **993,181** average executed non-Clifford gates (CCX + CCZ) per shot, rounded to
>   the nearest integer
> * **1,205** logical qubits
> * **11,000,000** total operations
>
> that correctly computes point addition on the elliptic curve secp256k1 across all 9,024
> pseudo-random distinct-x inputs deterministically derived from the circuit's own hash.

| | |
|---|---|
| Circuit SHA-256 | `artifacts/circuit_sha256.txt` |
| Groth16 proof | `artifacts/proof.bin` |
| Program vkey | `artifacts/vk.txt` (the SP1 program key hash — a public input, not the Groth16 VK) |
| Guest ELF | `artifacts/point-add-zk-guest.elf` |
| Guest ELF sha256 | `aca12ef22e078d3fa65875d5db021066633404da371bf69b39c7751440665180` |
| Built with | SP1 6.3.1, `cargo-prove` 8252c29, toolchain `succinct` (rustc 1.94.0-dev) |

Verification is against the shipped ELF, whose key is `artifacts/vk.txt`; the host refuses any other
key. Rebuilding `guest/` reproduces the program, but the key covers the ELF's build stamp as well, so a
byte-identical rebuild needs the toolchain above.

The same statement for Google Quantum AI et al., [arXiv:2603.28846](https://arxiv.org/abs/2603.28846)
Appendices A.1 and A.2 read 2,700,000 / 1,175 / 17,000,000 and 2,100,000 / 1,425 / 17,000,000.

## Hardening

Google's proof was forged by Trail of Bits in April 2026 ([Keegan
Ryan](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)):
a genuine Groth16 proof, verifying under their unmodified verifier, for a circuit that was not
reversible and whose Toffoli count the proof never actually measured. Google's resource estimates
were unaffected and upstream patched the guest in v2. The deserialization defence here is independently
derived; the operand-validation policy and the HMR/R conditioning follow upstream's v2 fixes, which
this guest transliterates (see NOTICE).

- **Unchecked deserialization.** An out-of-range opcode was UB that ran the gate but skipped the
  Toffoli counter. Here: no `unsafe`, no `rkyv`, counting and execution in one dispatch arm, and
  opcodes outside 0..=16 rejected (DebugPrint refused outright: the evaluator
  exempts it from every field check, and no real circuit contains one).
- **CCX operand aliasing.** Aliased operands give `q ^= cond & q` — a free reset, hence a NAND
  primitive. `validate_one` requires distinct operands.
- **HMR/R conditioning.** Allowed a reset without the matching phase randomisation, dodging the
  phase check. The reset and the randomisation share one `cond` mask, so neither applies alone.

Further checks. Every operand field neither the simulator nor the layout analyser reads is pinned to
its sentinel, so a validated op's encoding is canonical and unused fields cannot be stuffed with data.
And the four registers are checked for exact count, exact 256-slot width and distinct slots, not merely
slot type: a fifth register would otherwise widen the set of qubits exempted from the ancilla check.

## Checking it

Rust, `protobuf-compiler`, and [SP1](https://docs.succinct.xyz/) (`sp1up`). No GPU. The first build takes a couple of
minutes (~445 crates, ~1.6 GB), and the first `verify` downloads SP1's Groth16 artifacts (~7.9 GB,
once). Budget ~11 GB of disk. After that, verification is seconds.

```sh
cd host
cargo run --release -- verify --proof ../artifacts/proof.bin   # prints PROOF VALID + the statement
cargo run --release -- vk --elf ../artifacts/point-add-zk-guest.elf   # must equal artifacts/vk.txt
```

## Reproducing the proof

Requires the circuit and a GPU.

```sh
cd host && cargo run --release --features cuda -- prove \
    --ops /path/to/ops.bin --out /path/to/output \
    --max-toffoli 993181 --max-qubits 1205 --max-ops 11000000
```
