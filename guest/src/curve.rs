// Derived from zkp_ecc lib/src/weierstrass_elliptic_curve.rs (CC BY 4.0). See NOTICE.
use ruint::aliases::U256;

pub const P: U256 = U256::from_limbs([
    0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
]);
pub const GX: U256 = U256::from_limbs([
    0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC,
]);
pub const GY: U256 = U256::from_limbs([
    0x9C47D08FFB10D4B8, 0xFD17B448A6855419, 0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465,
]);
pub const A: U256 = U256::ZERO;
pub const N: U256 = U256::from_limbs([
    0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF,
]);

#[inline]
fn sub_mod(a: U256, b: U256, m: U256) -> U256 {
    if a >= b { a - b } else { m - (b - a) }
}

#[inline]
pub fn is_inf(x: U256, y: U256) -> bool {
    x.is_zero() && y.is_zero()
}

pub fn add(x1: U256, y1: U256, x2: U256, y2: U256) -> (U256, U256) {
    if is_inf(x1, y1) {
        return (x2, y2);
    }
    if is_inf(x2, y2) {
        return (x1, y1);
    }

    if x1 == x2 {
        if y1.add_mod(y2, P).is_zero() {
            return (U256::ZERO, U256::ZERO);
        }
        let num = x1.mul_mod(x1, P).mul_mod(U256::from(3), P).add_mod(A, P);
        let den = y1.mul_mod(U256::from(2), P);
        let lambda = num.mul_mod(den.inv_mod(P).expect("doubling denominator"), P);
        let x3 = sub_mod(lambda.mul_mod(lambda, P), x1.mul_mod(U256::from(2), P), P);
        let y3 = sub_mod(lambda.mul_mod(sub_mod(x1, x3, P), P), y1, P);
        return (x3, y3);
    }

    let num = sub_mod(y2, y1, P);
    let den = sub_mod(x2, x1, P);
    let lambda = num.mul_mod(den.inv_mod(P).expect("chord denominator"), P);
    let x3 = sub_mod(sub_mod(lambda.mul_mod(lambda, P), x1, P), x2, P);
    let y3 = sub_mod(lambda.mul_mod(sub_mod(x1, x3, P), P), y1, P);
    (x3, y3)
}

pub fn mul_reference(x: U256, y: U256, n: U256) -> (U256, U256) {
    let mut res = (U256::ZERO, U256::ZERO);
    let mut base = (x, y);
    let mut exp = n;
    while !exp.is_zero() {
        if exp.bit(0) {
            res = add(res.0, res.1, base.0, base.1);
        }
        base = add(base.0, base.1, base.0, base.1);
        exp >>= 1;
    }
    res
}

/// Equals `mul_reference` since k*G = (k mod n)*G.
#[cfg(feature = "precompiled-ec")]
pub fn mul_generator(k: U256) -> (U256, U256) {
    use elliptic_curve::{group::Group, sec1::ToEncodedPoint, PrimeField};

    let kr = k % N;
    if kr.is_zero() {
        return (U256::ZERO, U256::ZERO);
    }
    let fb = k256::FieldBytes::from(kr.to_be_bytes::<32>());
    let scalar = k256::Scalar::from_repr(fb).expect("reduced scalar is canonical");
    let pt = (<k256::ProjectivePoint as Group>::generator() * scalar).to_affine();
    let enc = pt.to_encoded_point(false);
    (
        U256::from_be_slice(enc.x().expect("affine x").as_slice()),
        U256::from_be_slice(enc.y().expect("affine y").as_slice()),
    )
}

#[cfg(not(feature = "precompiled-ec"))]
pub fn mul_generator(k: U256) -> (U256, U256) {
    mul_reference(GX, GY, k)
}
