// Exercises guest/src/ops.rs, which is derived from zkp_ecc (CC BY 4.0). See NOTICE.
// Streams a malicious prover could submit, plus the honest shape they must not resemble.

#[path = "../../guest/src/ops.rs"]
#[allow(dead_code)]
mod ops;

use ops::{check_register_composition, validate_one, Layout, RawOp, NO_BIT, NO_QUBIT, NO_REG};

const REGISTER: u32 = 1;
const APPEND: u32 = 2;
const X: u32 = 6;
const CX: u32 = 8;
const CCX: u32 = 13;
const DEBUG_PRINT: u32 = 17;

fn op(kind: u32) -> RawOp {
    RawOp {
        kind,
        pad: 0,
        q_control2: NO_QUBIT,
        q_control1: NO_QUBIT,
        q_target: NO_QUBIT,
        c_target: NO_BIT,
        c_condition: NO_BIT,
        r_target: NO_REG,
    }
}

fn well_formed_registers() -> Vec<RawOp> {
    let mut v = Vec::new();
    for r in 0..4u64 {
        let mut o = op(REGISTER);
        o.r_target = r;
        v.push(o);
    }
    for r in 0..4u64 {
        for i in 0..256u64 {
            let mut o = op(APPEND);
            o.r_target = r;
            if r < 2 {
                o.q_target = r * 256 + i;
            } else {
                o.c_target = (r - 2) * 256 + i;
            }
            v.push(o);
        }
    }
    v
}

fn layout_of(v: &[RawOp]) -> Layout {
    let mut a = ops::Analyzer::new();
    for o in v {
        a.feed(o);
    }
    a.finish()
}

#[test]
fn well_formed_stream_is_accepted() {
    let v = well_formed_registers();
    let l = layout_of(&v);
    assert!(check_register_composition(&l).is_ok(), "the honest shape must pass");
    for o in &v {
        assert!(validate_one(o, &l).is_ok(), "honest op rejected: kind {}", o.kind);
    }
}

#[test]
fn fifth_register_is_rejected() {
    let mut v = well_formed_registers();
    for q in 0..64u64 {
        let mut o = op(APPEND);
        o.r_target = 4;
        o.q_target = 512 + q;
        v.push(o);
    }
    let l = layout_of(&v);
    assert!(
        check_register_composition(&l).is_err(),
        "a fifth register must be rejected"
    );
}

#[test]
fn repeated_register_slot_is_rejected() {
    let mut v = well_formed_registers();
    v[4 + 7].q_target = v[4 + 6].q_target; // reg0 carries one qubit twice
    let l = layout_of(&v);
    assert!(
        check_register_composition(&l).is_err(),
        "a repeated qubit slot must be rejected"
    );

    let mut v = well_formed_registers();
    v[4 + 256].q_target = v[4].q_target; // reg1 slot 0 aliases reg0 slot 0
    let l = layout_of(&v);
    assert!(
        check_register_composition(&l).is_err(),
        "registers 0 and 1 must not share a qubit"
    );

    let mut v = well_formed_registers();
    v[4 + 768].c_target = v[4 + 512].c_target; // reg3 slot 0 aliases reg2 slot 0
    let l = layout_of(&v);
    assert!(
        check_register_composition(&l).is_err(),
        "registers 2 and 3 must not share a bit"
    );
}

#[test]
fn register_index_out_of_range_is_rejected() {
    let l = layout_of(&well_formed_registers());
    let mut o = op(APPEND);
    o.r_target = 4;
    o.q_target = 0;
    assert!(validate_one(&o, &l).is_err(), "r_target >= 4 must be rejected");

    let mut o = op(REGISTER);
    o.r_target = 1 << 40;
    assert!(validate_one(&o, &l).is_err(), "a huge r_target must be rejected");
}

#[test]
fn aliased_ccx_operands_are_rejected() {
    let l = layout_of(&well_formed_registers());
    for (a, b, c) in [(0u64, 1, 0), (0, 0, 1), (1, 0, 0)] {
        let mut o = op(CCX);
        o.q_target = a;
        o.q_control1 = b;
        o.q_control2 = c;
        assert!(validate_one(&o, &l).is_err(), "aliased CCX {a},{b},{c} must be rejected");
    }
}

#[test]
fn unread_fields_must_be_absent() {
    let l = layout_of(&well_formed_registers());

    let mut o = op(CX);
    o.q_target = 0;
    o.q_control1 = 1;
    o.r_target = 7; // ignored by the simulator, hashed by the transcript
    assert!(validate_one(&o, &l).is_err(), "r_target on a CX must be rejected");

    let mut o = op(X);
    o.q_target = 0;
    o.q_control2 = 5; // never read for X
    assert!(validate_one(&o, &l).is_err(), "q_control2 on an X must be rejected");
}

#[test]
fn debug_print_is_rejected() {
    let l = layout_of(&well_formed_registers());
    assert!(
        validate_one(&op(DEBUG_PRINT), &l).is_err(),
        "DebugPrint carries five unchecked fields and no circuit needs it"
    );
}

#[test]
fn out_of_range_opcode_is_rejected() {
    let l = layout_of(&well_formed_registers());
    for k in [18u32, 31, 45, 1 << 20] {
        assert!(validate_one(&op(k), &l).is_err(), "opcode {k} must be rejected");
    }
}

#[test]
fn non_zero_pad_is_rejected() {
    let l = layout_of(&well_formed_registers());
    let mut o = op(X);
    o.q_target = 0;
    o.pad = 1;
    assert!(validate_one(&o, &l).is_err(), "a non-zero pad must be rejected");
}
