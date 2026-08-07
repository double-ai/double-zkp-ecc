// Derived from zkp_ecc lib/src/circuit.rs and program/src/main.rs (CC BY 4.0). See NOTICE.
pub const NO_QUBIT: u64 = u64::MAX;
pub const NO_BIT: u64 = u64::MAX;
pub const NO_REG: u64 = u64::MAX;

pub const OP_BYTES: usize = 56;

pub const MAX_REGS: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    Neg = 0,
    Register = 1,
    AppendToRegister = 2,
    BitInvert = 3,
    BitStore0 = 4,
    BitStore1 = 5,
    X = 6,
    Z = 7,
    Cx = 8,
    Cz = 9,
    Swap = 10,
    R = 11,
    Hmr = 12,
    Ccx = 13,
    Ccz = 14,
    PushCondition = 15,
    PopCondition = 16,
    DebugPrint = 17,
}

impl Kind {
    fn from_u32(v: u32) -> Option<Self> {
        use Kind::*;
        Some(match v {
            0 => Neg, 1 => Register, 2 => AppendToRegister, 3 => BitInvert,
            4 => BitStore0, 5 => BitStore1, 6 => X, 7 => Z, 8 => Cx, 9 => Cz,
            10 => Swap, 11 => R, 12 => Hmr, 13 => Ccx, 14 => Ccz,
            15 => PushCondition, 16 => PopCondition, 17 => DebugPrint,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy)]
pub struct RawOp {
    pub kind: u32,
    pub pad: u32,
    pub q_control2: u64,
    pub q_control1: u64,
    pub q_target: u64,
    pub c_target: u64,
    pub c_condition: u64,
    pub r_target: u64,
}

impl RawOp {
    pub fn decode(rec: &[u8]) -> Self {
        debug_assert_eq!(rec.len(), OP_BYTES);
        let u64_at = |o: usize| u64::from_le_bytes(rec[o..o + 8].try_into().unwrap());
        Self {
            kind: u32::from_le_bytes(rec[0..4].try_into().unwrap()),
            pad: u32::from_le_bytes(rec[4..8].try_into().unwrap()),
            q_control2: u64_at(8),
            q_control1: u64_at(16),
            q_target: u64_at(24),
            c_target: u64_at(32),
            c_condition: u64_at(40),
            r_target: u64_at(48),
        }
    }

    pub fn fs_bytes(&self) -> [u8; 49] {
        let mut out = [0u8; 49];
        out[0] = self.kind as u8;
        for (i, v) in [
            self.q_control2, self.q_control1, self.q_target,
            self.c_target, self.c_condition, self.r_target,
        ]
        .iter()
        .enumerate()
        {
            out[1 + i * 8..9 + i * 8].copy_from_slice(&v.to_le_bytes());
        }
        out
    }
}

#[derive(Clone, Copy)]
pub struct Packed(pub u64);

const K_SH: u32 = 0; //  5 bits
const QC2_SH: u32 = 5; // 11
const QC1_SH: u32 = 16; // 11
const QT_SH: u32 = 27; // 11
const CT_SH: u32 = 38; // 13
const CC_SH: u32 = 51; // 13  -> 64 exactly
const Q_MASK: u64 = 0x7FF;
const C_MASK: u64 = 0x1FFF;

impl Packed {
    #[inline(always)]
    pub fn kind(self) -> u8 { ((self.0 >> K_SH) & 0x1F) as u8 }
    #[inline(always)]
    pub fn q_control2(self) -> u32 { ((self.0 >> QC2_SH) & Q_MASK) as u32 }
    #[inline(always)]
    pub fn q_control1(self) -> u32 { ((self.0 >> QC1_SH) & Q_MASK) as u32 }
    #[inline(always)]
    pub fn q_target(self) -> u32 { ((self.0 >> QT_SH) & Q_MASK) as u32 }
    #[inline(always)]
    pub fn c_target(self) -> u32 { ((self.0 >> CT_SH) & C_MASK) as u32 }
    #[inline(always)]
    pub fn c_condition(self) -> u32 { ((self.0 >> CC_SH) & C_MASK) as u32 }
}

pub const P_NO_QUBIT: u32 = Q_MASK as u32;
pub const P_NO_BIT: u32 = C_MASK as u32;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Qubit(u32),
    Bit(u32),
}

pub struct Layout {
    pub num_qubits: u64,
    pub num_bits: u64,
    pub registers: Vec<Vec<Slot>>,
}

impl Layout {
    pub fn fits(&self) -> bool {
        self.num_qubits < P_NO_QUBIT as u64 && self.num_bits < P_NO_BIT as u64
    }
}

pub struct Analyzer {
    num_qubits: u64,
    num_bits: u64,
    registers: Vec<Vec<Slot>>,
}

impl Analyzer {
    pub fn new() -> Self {
        Self { num_qubits: 0, num_bits: 0, registers: Vec::new() }
    }

    pub fn finish(self) -> Layout {
        Layout {
            num_qubits: self.num_qubits,
            num_bits: self.num_bits,
            registers: self.registers,
        }
    }

    pub fn feed(&mut self, op: &RawOp) {
        for q in [op.q_control2, op.q_control1, op.q_target] {
            if q != NO_QUBIT {
                self.num_qubits = self.num_qubits.max(q + 1);
            }
        }
        for c in [op.c_target, op.c_condition] {
            if c != NO_BIT {
                self.num_bits = self.num_bits.max(c + 1);
            }
        }
        match Kind::from_u32(op.kind) {
            Some(Kind::Register) => {
                let r = (op.r_target.min(MAX_REGS as u64)) as usize;
                if self.registers.len() <= r {
                    self.registers.resize(r + 1, Vec::new());
                }
            }
            Some(Kind::AppendToRegister) => {
                let r = (op.r_target.min(MAX_REGS as u64)) as usize;
                if self.registers.len() <= r {
                    self.registers.resize(r + 1, Vec::new());
                }
                if op.q_target != NO_QUBIT {
                    self.registers[r].push(Slot::Qubit(op.q_target as u32));
                } else {
                    self.registers[r].push(Slot::Bit(op.c_target as u32));
                }
            }
            _ => {}
        }
    }
}

pub fn validate_one(op: &RawOp, layout: &Layout) -> Result<(), &'static str> {
    const BANNED: u8 = 0;
    const ALLOWED: u8 = 1;
    const REQUIRED: u8 = 2;

    let kind = Kind::from_u32(op.kind).ok_or("op kind out of range")?;
    if op.pad != 0 {
        return Err("record pad must be zero");
    }

    for q in [op.q_control2, op.q_control1, op.q_target] {
        if q != NO_QUBIT && q >= layout.num_qubits {
            return Err("qubit operand out of range");
        }
    }
    for c in [op.c_target, op.c_condition] {
        if c != NO_BIT && c >= layout.num_bits {
            return Err("bit operand out of range");
        }
    }

    if op.q_target != NO_QUBIT && op.q_target == op.q_control1 {
        return Err("q_target == q_control1");
    }
    if op.q_target != NO_QUBIT && op.q_target == op.q_control2 {
        return Err("q_target == q_control2");
    }
    if op.q_control1 != NO_QUBIT && op.q_control1 == op.q_control2 {
        return Err("q_control1 == q_control2");
    }

    let (mut qt, mut qc1, mut qc2, mut ct, mut rt, mut cc) =
        (BANNED, BANNED, BANNED, BANNED, BANNED, BANNED);
    match kind {
        Kind::DebugPrint => return Err("DebugPrint is not accepted"),
        Kind::Register => rt = REQUIRED,
        Kind::AppendToRegister => {
            if (op.q_target == NO_QUBIT) == (op.c_target == NO_BIT) {
                return Err("AppendToRegister needs exactly one of q_target / c_target");
            }
            qt = ALLOWED;
            ct = ALLOWED;
            rt = REQUIRED;
        }
        Kind::Ccx | Kind::Ccz => {
            cc = ALLOWED;
            qt = REQUIRED;
            qc1 = REQUIRED;
            qc2 = REQUIRED;
        }
        Kind::Cx | Kind::Cz | Kind::Swap => {
            cc = ALLOWED;
            qt = REQUIRED;
            qc1 = REQUIRED;
        }
        Kind::X | Kind::Z | Kind::R => {
            cc = ALLOWED;
            qt = REQUIRED;
        }
        Kind::Neg => cc = ALLOWED,
        Kind::Hmr => {
            cc = ALLOWED;
            qt = REQUIRED;
            ct = REQUIRED;
        }
        Kind::BitInvert | Kind::BitStore0 | Kind::BitStore1 => {
            cc = ALLOWED;
            ct = REQUIRED;
        }
        Kind::PushCondition => cc = REQUIRED,
        Kind::PopCondition => {}
    }

    let chk = |flag: u8, v: u64, absent: u64, req: &'static str, ban: &'static str| {
        if flag == REQUIRED && v == absent {
            Err(req)
        } else if flag == BANNED && v != absent {
            Err(ban)
        } else {
            Ok(())
        }
    };
    chk(cc, op.c_condition, NO_BIT, "c_condition required", "c_condition banned")?;
    chk(qt, op.q_target, NO_QUBIT, "q_target required", "q_target banned")?;
    chk(qc1, op.q_control1, NO_QUBIT, "q_control1 required", "q_control1 banned")?;
    chk(qc2, op.q_control2, NO_QUBIT, "q_control2 required", "q_control2 banned")?;
    chk(ct, op.c_target, NO_BIT, "c_target required", "c_target banned")?;
    chk(rt, op.r_target, NO_REG, "r_target required", "r_target banned")?;

    if rt == REQUIRED && op.r_target >= MAX_REGS as u64 {
        return Err("register index out of range");
    }
    Ok(())
}

pub fn pack_one(o: &RawOp) -> Packed {
    let q = |v: u64| if v == NO_QUBIT { Q_MASK } else { assert!(v < Q_MASK); v };
    let c = |v: u64| if v == NO_BIT { C_MASK } else { assert!(v < C_MASK); v };
    Packed(
        ((o.kind as u64 & 0x1F) << K_SH)
            | (q(o.q_control2) << QC2_SH)
            | (q(o.q_control1) << QC1_SH)
            | (q(o.q_target) << QT_SH)
            | (c(o.c_target) << CT_SH)
            | (c(o.c_condition) << CC_SH),
    )
}

pub fn check_register_composition(layout: &Layout) -> Result<(), &'static str> {
    // Exactly four: a register 4+ would widen the ancilla exemption to any qubit it names.
    if layout.registers.len() != 4 {
        return Err("expected exactly four registers");
    }
    for r in 0..4 {
        if layout.registers[r].len() != 256 {
            return Err("each register must hold exactly 256 slots");
        }
    }
    for r in 0..2 {
        if !layout.registers[r].iter().all(|s| matches!(s, Slot::Qubit(_))) {
            return Err("register 0 and 1 must be qubits");
        }
    }
    for r in 2..4 {
        if !layout.registers[r].iter().all(|s| matches!(s, Slot::Bit(_))) {
            return Err("register 2 and 3 must be bits");
        }
    }
    // Distinct slots: a repeated one would carry two input bits on one wire.
    let mut seen_q = vec![false; layout.num_qubits as usize];
    let mut seen_b = vec![false; layout.num_bits as usize];
    for reg in &layout.registers {
        for slot in reg {
            let (seen, i) = match *slot {
                Slot::Qubit(q) => (&mut seen_q, q as usize),
                Slot::Bit(c) => (&mut seen_b, c as usize),
            };
            if seen[i] {
                return Err("register slots must be distinct");
            }
            seen[i] = true;
        }
    }
    Ok(())
}
