// Derived from zkp_ecc lib/src/sim.rs (CC BY 4.0). See NOTICE.
use crate::ops::{Packed, P_NO_BIT};

pub trait Coins {
    fn next_u64(&mut self) -> u64;
}

pub struct Sim {
    pub phase: u64,
    pub qubits: Vec<u64>,
    pub bits: Vec<u64>,
    pub toffoli: u64,
}

const NEG: u8 = 0;
const REGISTER: u8 = 1;
const APPEND: u8 = 2;
const BIT_INVERT: u8 = 3;
const BIT_STORE0: u8 = 4;
const BIT_STORE1: u8 = 5;
const X: u8 = 6;
const Z: u8 = 7;
const CX: u8 = 8;
const CZ: u8 = 9;
const SWAP: u8 = 10;
const R: u8 = 11;
const HMR: u8 = 12;
const CCX: u8 = 13;
const CCZ: u8 = 14;
const PUSH_COND: u8 = 15;
const POP_COND: u8 = 16;
const DEBUG_PRINT: u8 = 17;

impl Sim {
    pub fn new(num_qubits: usize, num_bits: usize) -> Self {
        Self {
            phase: 0,
            qubits: vec![0; num_qubits],
            bits: vec![0; num_bits],
            toffoli: 0,
        }
    }

    pub fn clear_for_shot(&mut self) {
        self.qubits.iter_mut().for_each(|e| *e = 0);
        self.bits.iter_mut().for_each(|e| *e = 0);
        self.phase = 0;
    }

    #[inline(always)]
    fn q(&self, i: u32) -> u64 { self.qubits[i as usize] }
    #[inline(always)]
    fn qm(&mut self, i: u32) -> &mut u64 { &mut self.qubits[i as usize] }
    #[inline(always)]
    fn b(&self, i: u32) -> u64 { self.bits[i as usize] }
    #[inline(always)]
    fn bm(&mut self, i: u32) -> &mut u64 { &mut self.bits[i as usize] }

    pub fn apply(&mut self, ops: &[Packed], coins: &mut impl Coins) {
        let mut stack: Vec<u64> = Vec::with_capacity(64);
        let mut base = u64::MAX;

        for op in ops {
            let kind = op.kind();
            let cc = op.c_condition();
            let mut cond = base;
            if cc != P_NO_BIT {
                cond &= self.b(cc);
            }

            // Counting and execution share one arm: no kind can skip the counter.
            match kind {
                CCX => {
                    self.toffoli += cond.count_ones() as u64;
                    let v = cond & self.q(op.q_control1()) & self.q(op.q_control2());
                    *self.qm(op.q_target()) ^= v;
                }
                CX => {
                    let v = cond & self.q(op.q_control1());
                    *self.qm(op.q_target()) ^= v;
                }
                SWAP => {
                    let (a, t) = (op.q_control1(), op.q_target());
                    let mut qa = self.q(a);
                    let mut qt = self.q(t);
                    qa ^= qt;
                    qt ^= cond & qa;
                    qa ^= qt;
                    *self.qm(a) = qa;
                    *self.qm(t) = qt;
                }
                X => *self.qm(op.q_target()) ^= cond,
                CCZ => {
                    self.toffoli += cond.count_ones() as u64;
                    let v = cond
                        & self.q(op.q_target())
                        & self.q(op.q_control1())
                        & self.q(op.q_control2());
                    self.phase ^= v;
                }
                CZ => {
                    let v = cond & self.q(op.q_target()) & self.q(op.q_control1());
                    self.phase ^= v;
                }
                Z => {
                    let v = cond & self.q(op.q_target());
                    self.phase ^= v;
                }
                NEG => self.phase ^= cond,
                HMR => {
                    let rng = coins.next_u64();
                    let t = op.q_target();
                    let ct = op.c_target();
                    *self.bm(ct) &= !cond;
                    *self.bm(ct) ^= rng & cond;
                    self.phase ^= self.q(t) & rng & cond;
                    *self.qm(t) &= !cond;
                }
                R => {
                    let rng = coins.next_u64();
                    let t = op.q_target();
                    self.phase ^= self.q(t) & rng & cond;
                    *self.qm(t) &= !cond;
                }
                BIT_INVERT => *self.bm(op.c_target()) ^= cond,
                BIT_STORE0 => *self.bm(op.c_target()) &= !cond,
                BIT_STORE1 => *self.bm(op.c_target()) |= cond,
                APPEND | REGISTER | DEBUG_PRINT => {}
                PUSH_COND => {
                    stack.push(base);
                    base &= self.b(cc);
                }
                POP_COND => {
                    base = stack.pop().expect("condition stack underflow");
                }
                _ => panic!("unknown op kind"),
            }
        }
    }

    pub fn get_register(&self, reg: &[crate::ops::Slot], shot: usize) -> ruint::aliases::U256 {
        use crate::ops::Slot;
        let mut v = ruint::aliases::U256::ZERO;
        for (i, s) in reg.iter().enumerate() {
            let bit = match *s {
                Slot::Qubit(id) => (self.q(id) >> shot) & 1,
                Slot::Bit(id) => (self.b(id) >> shot) & 1,
            };
            v.set_bit(i, bit != 0);
        }
        v
    }

    pub fn set_register(&mut self, reg: &[crate::ops::Slot], val: ruint::aliases::U256, shot: usize) {
        use crate::ops::Slot;
        let m = 1u64 << shot;
        for (i, s) in reg.iter().enumerate() {
            let one = val.bit(i);
            match *s {
                Slot::Qubit(id) => {
                    if one { *self.qm(id) |= m } else { *self.qm(id) &= !m }
                }
                Slot::Bit(id) => {
                    if one { *self.bm(id) |= m } else { *self.bm(id) &= !m }
                }
            }
        }
    }
}
