// Reference arithmetic derived from zkp_ecc (CC BY 4.0). See NOTICE.
use elliptic_curve::{group::Group, sec1::ToEncodedPoint, PrimeField};
use ruint::aliases::U256;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const NUM_TESTS: usize = 9024;
const OP_BYTES: usize = 56;
const FS_DOMAIN: &[u8] = b"quantum_ecc-fiat-shamir-v2";

fn h(s: &str) -> U256 { U256::from_str_radix(s, 16).unwrap() }
fn p() -> U256 { h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F") }
fn n() -> U256 { h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") }
fn gx() -> U256 { h("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798") }
fn gy() -> U256 { h("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8") }

fn sub_mod(a: U256, b: U256, m: U256) -> U256 { if a >= b { a - b } else { m - (b - a) } }

fn add(x1: U256, y1: U256, x2: U256, y2: U256) -> (U256, U256) {
    let m = p();
    if x1.is_zero() && y1.is_zero() { return (x2, y2); }
    if x2.is_zero() && y2.is_zero() { return (x1, y1); }
    if x1 == x2 {
        if y1.add_mod(y2, m).is_zero() { return (U256::ZERO, U256::ZERO); }
        let num = x1.mul_mod(x1, m).mul_mod(U256::from(3u64), m);
        let den = y1.mul_mod(U256::from(2u64), m);
        let l = num.mul_mod(den.inv_mod(m).unwrap(), m);
        let x3 = sub_mod(l.mul_mod(l, m), x1.mul_mod(U256::from(2u64), m), m);
        return (x3, sub_mod(l.mul_mod(sub_mod(x1, x3, m), m), y1, m));
    }
    let l = sub_mod(y2, y1, m).mul_mod(sub_mod(x2, x1, m).inv_mod(m).unwrap(), m);
    let x3 = sub_mod(sub_mod(l.mul_mod(l, m), x1, m), x2, m);
    (x3, sub_mod(l.mul_mod(sub_mod(x1, x3, m), m), y1, m))
}

fn mul_reference(k: U256) -> (U256, U256) {
    let (mut res, mut base, mut e) = ((U256::ZERO, U256::ZERO), (gx(), gy()), k);
    while !e.is_zero() {
        if e.bit(0) { res = add(res.0, res.1, base.0, base.1); }
        base = add(base.0, base.1, base.0, base.1);
        e >>= 1;
    }
    res
}

fn mul_generator(k: U256) -> (U256, U256) {
    let kr = k % n();
    if kr.is_zero() { return (U256::ZERO, U256::ZERO); }
    let s = k256::Scalar::from_repr(k256::FieldBytes::from(kr.to_be_bytes::<32>())).unwrap();
    let e = (<k256::ProjectivePoint as Group>::generator() * s).to_affine().to_encoded_point(false);
    (U256::from_be_slice(e.x().unwrap().as_slice()), U256::from_be_slice(e.y().unwrap().as_slice()))
}

#[test]
fn degenerate_scalars_agree() {
    for k in [U256::ZERO, U256::from(1u64), U256::from(2u64), n(),
              n() - U256::from(1u64), n() + U256::from(1u64), U256::MAX] {
        assert_eq!(mul_reference(k), mul_generator(k), "divergence at k = {k:#x}");
    }
}

#[test]
fn transcript_scalars_agree() {
    let Ok(path) = std::env::var("PARITY_OPS") else {
        eprintln!("PARITY_OPS unset - skipping (needs the circuit's ops.bin, which is not published)");
        return;
    };
    let blob = std::fs::read(&path).expect("read ops.bin");
    assert_eq!(&blob[0..8], b"QECCOPSZ", "bad magic");
    let body = zstd::stream::decode_all(&blob[16..]).expect("zstd decode");
    let n_ops = body.len() / OP_BYTES;

    let mut fs = Shake256::default();
    fs.update(FS_DOMAIN);
    fs.update(&(n_ops as u64).to_le_bytes());
    let mut rec = [0u8; 49];
    for i in 0..n_ops {
        let r = &body[i * OP_BYTES..(i + 1) * OP_BYTES];
        rec[0] = r[0];
        rec[1..49].copy_from_slice(&r[8..56]);
        fs.update(&rec);
    }
    let mut xof = fs.finalize_xof();

    let mut checked = 0usize;
    for i in 0..NUM_TESTS {
        for w in 0..2 {
            let mut b = [0u8; 32];
            xof.read(&mut b);
            let k = U256::from_le_bytes(b);
            assert_eq!(mul_reference(k), mul_generator(k),
                       "divergence at test {i}, scalar {w}, k = {k:#x}");
            checked += 1;
        }
    }
    assert_eq!(checked, 2 * NUM_TESTS);
    eprintln!("{checked}/{} transcript scalars bit-identical", 2 * NUM_TESTS);
}
